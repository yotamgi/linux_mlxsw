/*
 * drivers/net/ethernet/mellanox/mlxsw/spectrum_mr_tcam.c
 * Copyright (c) 2017 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2017 Yotam Gigi <yotamg@mellanox.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/parman.h>

#include "reg.h"
#include "spectrum.h"
#include "core_acl_flex_actions.h"
#include "spectrum_mr.h"

struct mlxsw_sp_mr_tcam_region {
	struct mlxsw_sp *mlxsw_sp;
	enum mlxsw_reg_rtar_key_type rtar_key_type;
	struct parman *parman;
	struct parman_prio *parman_prios;
};

struct mlxsw_sp_mr_tcam {
	struct mlxsw_sp_mr_tcam_region ipv4_tcam_region;
	u32 max_prio;
};

struct mlxsw_sp_mr_rigr2_entry {
	struct list_head list;
	u32 kvdl_index;
	int num_erifs;
	u16 erif_indices[MLXSW_REG_RIGR2_MAX_ERIFS];
	bool synced;
};

struct mlxsw_sp_mr_tcam_erif_list {
	struct list_head rigr2_entries;
};

static bool
mlxsw_sp_mr_rigr2_entry_full(struct mlxsw_sp *mlxsw_sp,
			     struct mlxsw_sp_mr_rigr2_entry *rigr2_entry)
{
	int erif_list_entries = MLXSW_CORE_RES_GET(mlxsw_sp->core,
						   MC_ERIF_LIST_ENTRIES);

	return rigr2_entry->num_erifs == erif_list_entries;
}

static struct mlxsw_sp_mr_tcam_erif_list *mlxsw_sp_mr_erif_list_create(void)
{
	struct mlxsw_sp_mr_tcam_erif_list *erif_list;

	erif_list = kzalloc(sizeof(*erif_list), GFP_KERNEL);
	if (!erif_list)
		return NULL;

	INIT_LIST_HEAD(&erif_list->rigr2_entries);
	return erif_list;
}

static bool
mlxsw_sp_mr_erif_list_empty(struct mlxsw_sp_mr_tcam_erif_list *erif_list)
{
	return list_empty(&erif_list->rigr2_entries);
}

static u32
mlxsw_sp_mr_erif_list_kvdl_index(struct mlxsw_sp_mr_tcam_erif_list *erif_list)
{
	if (WARN_ON(mlxsw_sp_mr_erif_list_empty(erif_list)))
		return 0;
	return list_first_entry(&erif_list->rigr2_entries,
				struct mlxsw_sp_mr_rigr2_entry,
				list)->kvdl_index;
}

#define MLXSW_SP_KVDL_RIGR2_SIZE 1

static struct mlxsw_sp_mr_rigr2_entry *
mlxsw_sp_mr_rigr2_entry_create(struct mlxsw_sp *mlxsw_sp,
			       struct mlxsw_sp_mr_tcam_erif_list *erif_list)
{
	struct mlxsw_sp_mr_rigr2_entry *rigr2_entry;
	int err;

	rigr2_entry = kzalloc(sizeof(*rigr2_entry), GFP_KERNEL);
	if (!rigr2_entry)
		return ERR_PTR(-ENOMEM);
	err = mlxsw_sp_kvdl_alloc(mlxsw_sp, MLXSW_SP_KVDL_RIGR2_SIZE,
				  &rigr2_entry->kvdl_index);
	if (err) {
		kfree(rigr2_entry);
		return ERR_PTR(err);
	}

	list_add_tail(&rigr2_entry->list, &erif_list->rigr2_entries);
	return rigr2_entry;
}

static void
mlxsw_sp_mr_rigr2_entry_destroy(struct mlxsw_sp *mlxsw_sp,
				struct mlxsw_sp_mr_rigr2_entry *rigr2_entry)
{
	list_del(&rigr2_entry->list);
	mlxsw_sp_kvdl_free(mlxsw_sp, rigr2_entry->kvdl_index);
	kfree(rigr2_entry);
}

static int
mlxsw_sp_mr_erif_list_add(struct mlxsw_sp *mlxsw_sp,
			  struct mlxsw_sp_mr_tcam_erif_list *erif_list,
			  u16 erif_index)
{
	struct mlxsw_sp_mr_rigr2_entry *last_entry;

	/* If either there is no erif_entry or the last one is full, allocate a
	 * new one.
	 */
	if (list_empty(&erif_list->rigr2_entries)) {
		last_entry = mlxsw_sp_mr_rigr2_entry_create(mlxsw_sp,
							    erif_list);
		if (IS_ERR(last_entry))
			return PTR_ERR(last_entry);
	} else {
		last_entry = list_last_entry(&erif_list->rigr2_entries,
					     struct mlxsw_sp_mr_rigr2_entry,
					     list);
		last_entry->synced = false;
		if (mlxsw_sp_mr_rigr2_entry_full(mlxsw_sp, last_entry)) {
			last_entry = mlxsw_sp_mr_rigr2_entry_create(mlxsw_sp,
								    erif_list);
			if (IS_ERR(last_entry))
				return PTR_ERR(last_entry);
		}
	}

	/* Add the eRIF to the last entry's last index */
	last_entry->erif_indices[last_entry->num_erifs++] = erif_index;
	return 0;
}

static void
mlxsw_sp_mr_erif_list_destroy(struct mlxsw_sp *mlxsw_sp,
			      struct mlxsw_sp_mr_tcam_erif_list *erif_list)
{
	struct mlxsw_sp_mr_rigr2_entry *rigr2_entry, *tmp;

	list_for_each_entry_safe(rigr2_entry, tmp, &erif_list->rigr2_entries,
				 list)
		mlxsw_sp_mr_rigr2_entry_destroy(mlxsw_sp, rigr2_entry);
	kfree(erif_list);
}

static int
mlxsw_sp_mr_erif_list_commit(struct mlxsw_sp *mlxsw_sp,
			     struct mlxsw_sp_mr_tcam_erif_list *erif_list)
{
	struct mlxsw_sp_mr_rigr2_entry *rigr2_entry;
	char rigr2_pl[MLXSW_REG_RIGR2_LEN];
	bool first = true;
	bool set = false;
	int err;
	int i;

	if (list_empty(&erif_list->rigr2_entries))
		return -EINVAL;

	list_for_each_entry(rigr2_entry, &erif_list->rigr2_entries, list) {
		if (rigr2_entry->synced)
			continue;

		if (!first) {
			int next = rigr2_entry->kvdl_index;

			mlxsw_reg_rigr2_vnext_set(rigr2_pl, true);
			mlxsw_reg_rigr2_next_rigr_index_set(rigr2_pl, next);
			err = mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(rigr2),
					      rigr2_pl);
			if (err)
				/* No need of a rollback here because this
				 * hardware entry should not be pointed yet.
				 */
				return err;
		}
		MLXSW_REG_ZERO(rigr2, rigr2_pl);
		mlxsw_reg_rigr2_rigr_index_set(rigr2_pl,
					       rigr2_entry->kvdl_index);
		rigr2_entry->synced = true;
		for (i = 0; i < rigr2_entry->num_erifs; i++) {
			u16 erif_index = rigr2_entry->erif_indices[i];

			mlxsw_reg_rigr2_erif_entry_v_set(rigr2_pl, i, true);
			mlxsw_reg_rigr2_erif_entry_erif_set(rigr2_pl, i,
							    erif_index);
		}
		first = false;
		set = true;
	}

	if (set)
		return mlxsw_reg_write(mlxsw_sp->core,  MLXSW_REG(rigr2), rigr2_pl);
	else
		return 0;
}

struct mlxsw_sp_mr_tcam_route {
	struct mlxsw_sp_mr_tcam_erif_list *erif_list;
	struct mlxsw_afa_block *afa_block;
	u32 counter_index;
	struct parman_item parman_item;
	struct parman_prio *parman_prio;
	enum mlxsw_sp_mr_route_action action;
	struct mlxsw_sp_mr_route_key key;
	u16 irif_index;
	u16 min_mtu;
};

static struct mlxsw_afa_block *
mlxsw_sp_mr_tcam_afa_block_create(struct mlxsw_sp *mlxsw_sp,
				  enum mlxsw_sp_mr_route_action route_action,
				  u16 irif_index, u32 counter_index,
				  u16 min_mtu,
				  struct mlxsw_sp_mr_tcam_erif_list *erif_list)
{
	struct mlxsw_afa_block *afa_block;
	u32 kvdl_index;
	int err;

	afa_block = mlxsw_afa_block_create(mlxsw_sp->afa);
	if (IS_ERR(afa_block))
		return afa_block;

	err = mlxsw_afa_block_append_counter(afa_block, counter_index);
	if (err)
		goto err;

	switch (route_action) {
	case MLXSW_SP_MR_ROUTE_ACTION_TRAP:
		err = mlxsw_afa_block_append_trap(afa_block,
						  MLXSW_TRAP_ID_ACL1);
		if (err)
			goto err;
		break;
	case MLXSW_SP_MR_ROUTE_ACTION_FORWARD:
		/* If we are about to append a multicast router action, commit
		 * the erif_list.
		 */
		err = mlxsw_sp_mr_erif_list_commit(mlxsw_sp, erif_list);
		if (err)
			goto err;

		kvdl_index = mlxsw_sp_mr_erif_list_kvdl_index(erif_list);
		err = mlxsw_afa_block_append_mcrouter(afa_block, irif_index,
						      min_mtu, false,
						      kvdl_index);
		if (err)
			goto err;
		break;
	default:
		err = -EINVAL;
		goto err;
	}

	err = mlxsw_afa_block_commit(afa_block);
	if (err)
		goto err;
	return afa_block;
err:
	mlxsw_afa_block_destroy(afa_block);
	return ERR_PTR(err);
}

static void
mlxsw_sp_mr_tcam_afa_block_destroy(struct mlxsw_afa_block *afa_block)
{
	mlxsw_afa_block_destroy(afa_block);
}

static int mlxsw_sp_mr_tcam_route_write(struct mlxsw_sp *mlxsw_sp,
					struct parman_item *parman_item,
					struct mlxsw_sp_mr_route_key *key,
					struct mlxsw_afa_block *afa_block)
{
	char rmft2_pl[MLXSW_REG_RMFT2_LEN];

	switch (key->proto) {
	case MLXSW_SP_L3_PROTO_IPV4:
		mlxsw_reg_rmft2_ipv4_pack(rmft2_pl, true, parman_item->index,
					  key->vrid,
					  MLXSW_REG_RMFT2_IRIF_MASK_IGNORE, 0,
					  *(u32 *) &key->group,
					  *(u32 *) &key->group_mask,
					  *(u32 *) &key->source,
					  *(u32 *) &key->source_mask,
					  mlxsw_afa_block_first_set(afa_block));
		break;
	case MLXSW_SP_L3_PROTO_IPV6:
	default:
		WARN_ON_ONCE(1);
	}

	return mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(rmft2), rmft2_pl);
}

static int mlxsw_sp_mr_tcam_route_remove(struct mlxsw_sp *mlxsw_sp, int vrid,
					 struct parman_item *parman_item)
{
	char rmft2_pl[MLXSW_REG_RMFT2_LEN];

	mlxsw_reg_rmft2_ipv4_pack(rmft2_pl, false, parman_item->index, vrid,
				  0, 0, 0, 0, 0, 0, NULL);

	return mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(rmft2), rmft2_pl);
}

static int
mlxsw_sp_mr_tcam_erif_populate(struct mlxsw_sp *mlxsw_sp,
			       struct mlxsw_sp_mr_tcam_erif_list *erif_list,
			       struct mlxsw_sp_mr_route_value *route_value)
{
	int err;
	int i;

	for (i = 0; i < route_value->erif_num; i++) {
		u16 erif_index = route_value->erif_indices[i];

		err = mlxsw_sp_mr_erif_list_add(mlxsw_sp, erif_list,
						erif_index);
		if (err)
			return err;
	}
	return 0;
}

static int
mlxsw_sp_mr_tcam_route_parman_item_add(struct mlxsw_sp_mr_tcam *mr_tcam,
				       struct mlxsw_sp_mr_tcam_route *route,
				       enum mlxsw_sp_mr_route_prio prio)
{
	struct parman_prio *parman_prio = NULL;
	int err;

	switch (route->key.proto) {
	case MLXSW_SP_L3_PROTO_IPV4:
		parman_prio = &mr_tcam->ipv4_tcam_region.parman_prios[prio];
		err = parman_item_add(mr_tcam->ipv4_tcam_region.parman,
				      parman_prio, &route->parman_item);
		if (err)
			return err;
		break;
	case MLXSW_SP_L3_PROTO_IPV6:
	default:
		WARN_ON_ONCE(1);
	}
	route->parman_prio = parman_prio;
	return 0;
}

static void
mlxsw_sp_mr_tcam_route_parman_item_remove(struct mlxsw_sp_mr_tcam *mr_tcam,
					  struct mlxsw_sp_mr_tcam_route *route)
{
	switch (route->key.proto) {
	case MLXSW_SP_L3_PROTO_IPV4:
		parman_item_remove(mr_tcam->ipv4_tcam_region.parman,
				   route->parman_prio, &route->parman_item);
		break;
	case MLXSW_SP_L3_PROTO_IPV6:
	default:
		WARN_ON_ONCE(1);
	}
}

static int
mlxsw_sp_mr_tcam_route_create(struct mlxsw_sp *mlxsw_sp, void *priv,
			      void *route_priv,
			      struct mlxsw_sp_mr_route_params *route_params)
{
	struct mlxsw_sp_mr_tcam_route *route = route_priv;
	struct mlxsw_sp_mr_tcam *mr_tcam = priv;
	int err;

	route->key = route_params->key;
	route->irif_index = route_params->value.irif_index;
	route->min_mtu = route_params->value.min_mtu;
	route->action = route_params->value.route_action;

	/* Create the egress RIFs list */
	route->erif_list = mlxsw_sp_mr_erif_list_create();
	if (!route->erif_list)
		return -ENOMEM;
	err = mlxsw_sp_mr_tcam_erif_populate(mlxsw_sp, route->erif_list,
					     &route_params->value);
	if (err)
		goto err_erif_populate;

	/* Create the flow counter */
	err = mlxsw_sp_flow_counter_alloc(mlxsw_sp, &route->counter_index);
	if (err)
		goto err_flow_counter_alloc;

	/* Create the flexible action block */
	route->afa_block = mlxsw_sp_mr_tcam_afa_block_create(mlxsw_sp,
							     route->action,
							     route->irif_index,
							     route->counter_index,
							     route->min_mtu,
							     route->erif_list);
	if (IS_ERR(route->afa_block)) {
		err = PTR_ERR(route->afa_block);
		goto err_afa_block_create;
	}

	/* Allocate place in the TCAM */
	err = mlxsw_sp_mr_tcam_route_parman_item_add(mr_tcam, route,
						     route_params->prio);
	if (err)
		goto err_parman_item_add;

	/* Write the route to the TCAM */
	err = mlxsw_sp_mr_tcam_route_write(mlxsw_sp, &route->parman_item,
					   &route->key, route->afa_block);
	if (err)
		goto err_route_write;
	return 0;

err_route_write:
	mlxsw_sp_mr_tcam_route_parman_item_remove(mr_tcam, route);
err_parman_item_add:
	mlxsw_sp_mr_tcam_afa_block_destroy(route->afa_block);
err_afa_block_create:
	mlxsw_sp_flow_counter_free(mlxsw_sp, route->counter_index);
err_flow_counter_alloc:
err_erif_populate:
	mlxsw_sp_mr_erif_list_destroy(mlxsw_sp, route->erif_list);
	return err;
}

static void mlxsw_sp_mr_tcam_route_destroy(struct mlxsw_sp *mlxsw_sp,
					   void *priv, void *route_priv)
{
	struct mlxsw_sp_mr_tcam_route *route = route_priv;
	struct mlxsw_sp_mr_tcam *mr_tcam = priv;

	mlxsw_sp_mr_tcam_route_remove(mlxsw_sp, route->key.vrid,
				      &route->parman_item);
	mlxsw_sp_mr_tcam_route_parman_item_remove(mr_tcam, route);
	mlxsw_sp_mr_tcam_afa_block_destroy(route->afa_block);
	mlxsw_sp_flow_counter_free(mlxsw_sp, route->counter_index);
	mlxsw_sp_mr_erif_list_destroy(mlxsw_sp, route->erif_list);
}

static int mlxsw_sp_mr_tcam_route_stats(struct mlxsw_sp *mlxsw_sp,
					void *route_priv, u64 *packets,
					u64 *bytes)
{
	struct mlxsw_sp_mr_tcam_route *route = route_priv;

	return mlxsw_sp_flow_counter_get(mlxsw_sp, route->counter_index,
					 packets, bytes);
}

static int
mlxsw_sp_mr_tcam_route_action_update(struct mlxsw_sp *mlxsw_sp,
				     void *route_priv,
				     enum mlxsw_sp_mr_route_action route_action)
{
	struct mlxsw_sp_mr_tcam_route *route = route_priv;
	struct mlxsw_afa_block *afa_block;
	int err;

	/* Create a new flexible action block */
	afa_block = mlxsw_sp_mr_tcam_afa_block_create(mlxsw_sp, route_action,
						      route->irif_index,
						      route->counter_index,
						      route->min_mtu,
						      route->erif_list);
	if (IS_ERR(afa_block))
		return PTR_ERR(afa_block);

	/* Update the TCAM route entry */
	err = mlxsw_sp_mr_tcam_route_write(mlxsw_sp, &route->parman_item,
					   &route->key, afa_block);
	if (err)
		goto err;

	/* Delete the old one */
	mlxsw_sp_mr_tcam_afa_block_destroy(route->afa_block);
	route->afa_block = afa_block;
	route->action = route_action;
	return 0;
err:
	mlxsw_sp_mr_tcam_afa_block_destroy(afa_block);
	return err;
}

static int mlxsw_sp_mr_tcam_route_min_mtu_update(struct mlxsw_sp *mlxsw_sp,
						 void *route_priv, u16 min_mtu)
{
	struct mlxsw_sp_mr_tcam_route *route = route_priv;
	struct mlxsw_afa_block *afa_block;
	int err;

	/* Create a new flexible action block */
	afa_block = mlxsw_sp_mr_tcam_afa_block_create(mlxsw_sp,
						      route->action,
						      route->irif_index,
						      route->counter_index,
						      min_mtu,
						      route->erif_list);
	if (IS_ERR(afa_block))
		return PTR_ERR(afa_block);

	/* Update the TCAM route entry */
	err = mlxsw_sp_mr_tcam_route_write(mlxsw_sp, &route->parman_item,
					   &route->key, afa_block);
	if (err)
		goto err;

	/* Delete the old one */
	mlxsw_sp_mr_tcam_afa_block_destroy(route->afa_block);
	route->afa_block = afa_block;
	route->min_mtu = min_mtu;
	return 0;
err:
	mlxsw_sp_mr_tcam_afa_block_destroy(afa_block);
	return err;
}

static int mlxsw_sp_mr_tcam_route_irif_update(struct mlxsw_sp *mlxsw_sp,
					      void *route_priv, u16 irif_index)
{
	struct mlxsw_sp_mr_tcam_route *route = route_priv;

	if (route->action != MLXSW_SP_MR_ROUTE_ACTION_TRAP)
		return -EINVAL;
	route->irif_index = irif_index;
	return 0;
}

static int mlxsw_sp_mr_tcam_route_erif_add(struct mlxsw_sp *mlxsw_sp,
					   void *route_priv, u16 erif_index)
{
	struct mlxsw_sp_mr_tcam_route *route = route_priv;
	int err;

	err = mlxsw_sp_mr_erif_list_add(mlxsw_sp, route->erif_list,
					erif_index);
	if (err)
		return err;

	/* Commit the action only if the route action is not TRAP */
	if (route->action != MLXSW_SP_MR_ROUTE_ACTION_TRAP)
		return mlxsw_sp_mr_erif_list_commit(mlxsw_sp,
						    route->erif_list);
	return 0;
}

static int mlxsw_sp_mr_tcam_route_erif_del(struct mlxsw_sp *mlxsw_sp,
					   void *route_priv, u16 erif_index)
{
	struct mlxsw_sp_mr_tcam_route *route = route_priv;
	struct mlxsw_sp_mr_rigr2_entry *rigr2_entry;
	struct mlxsw_sp_mr_tcam_erif_list *erif_list;
	struct mlxsw_afa_block *afa_block;
	int err;
	int i;

	/* Create a copy of the original erif_list without the deleted entry */
	erif_list = mlxsw_sp_mr_erif_list_create();
	if (!erif_list)
		return -ENOMEM;

	list_for_each_entry(rigr2_entry, &route->erif_list->rigr2_entries, list) {
		for (i = 0; i < rigr2_entry->num_erifs; i++) {
			u16 curr_erif = rigr2_entry->erif_indices[i];

			if (curr_erif == erif_index)
				continue;
			err = mlxsw_sp_mr_erif_list_add(mlxsw_sp, erif_list,
							curr_erif);
			if (err)
				goto err_erif_list_add;
		}
	}

	/* Create the flexible action block pointing to the new erif_list */
	afa_block = mlxsw_sp_mr_tcam_afa_block_create(mlxsw_sp, route->action,
						      route->irif_index,
						      route->counter_index,
						      route->min_mtu,
						      erif_list);
	if (IS_ERR(afa_block)) {
		err = PTR_ERR(afa_block);
		goto err_afa_block_create;
	}

	/* Update the TCAM route entry */
	err = mlxsw_sp_mr_tcam_route_write(mlxsw_sp, &route->parman_item,
					   &route->key, afa_block);
	if (err)
		goto err_route_write;

	mlxsw_sp_mr_tcam_afa_block_destroy(route->afa_block);
	mlxsw_sp_mr_erif_list_destroy(mlxsw_sp, route->erif_list);
	route->afa_block = afa_block;
	route->erif_list = erif_list;
	return 0;

err_route_write:
	mlxsw_sp_mr_tcam_afa_block_destroy(afa_block);
err_afa_block_create:
err_erif_list_add:
	mlxsw_sp_mr_erif_list_destroy(mlxsw_sp, erif_list);
	return err;
}

static int
mlxsw_sp_mr_tcam_route_update(struct mlxsw_sp *mlxsw_sp, void *route_priv,
			      struct mlxsw_sp_mr_route_value *route_value)
{
	struct mlxsw_sp_mr_tcam_route *route = route_priv;
	struct mlxsw_sp_mr_tcam_erif_list *erif_list;
	struct mlxsw_afa_block *afa_block;
	int err;

	/* Create a new erif_list */
	erif_list = mlxsw_sp_mr_erif_list_create();
	if (!erif_list)
		return -ENOMEM;
	err = mlxsw_sp_mr_tcam_erif_populate(mlxsw_sp, erif_list, route_value);
	if (err)
		goto err_erif_populate;

	/* Create the flexible action block pointing to the new erif_list */
	afa_block = mlxsw_sp_mr_tcam_afa_block_create(mlxsw_sp,
						      route_value->route_action,
						      route_value->irif_index,
						      route->counter_index,
						      route_value->min_mtu,
						      erif_list);
	if (IS_ERR(afa_block)) {
		err = PTR_ERR(afa_block);
		goto err_afa_block_create;
	}

	/* Update the TCAM route entry */
	err = mlxsw_sp_mr_tcam_route_write(mlxsw_sp, &route->parman_item,
					   &route->key, afa_block);
	if (err)
		goto err_route_write;

	mlxsw_sp_mr_tcam_afa_block_destroy(route->afa_block);
	mlxsw_sp_mr_erif_list_destroy(mlxsw_sp, route->erif_list);
	route->afa_block = afa_block;
	route->erif_list = erif_list;
	route->action = route_value->route_action;
	route->irif_index = route_value->irif_index;
	route->min_mtu = route_value->min_mtu;
	return 0;

err_route_write:
	mlxsw_sp_mr_tcam_afa_block_destroy(afa_block);
err_afa_block_create:
err_erif_populate:
	mlxsw_sp_mr_erif_list_destroy(mlxsw_sp, erif_list);
	return err;
}

#define MLXSW_SP_MR_TCAM_REGION_BASE_COUNT 16
#define MLXSW_SP_MR_TCAM_REGION_RESIZE_STEP 16

static int
mlxsw_sp_mr_tcam_region_alloc(struct mlxsw_sp_mr_tcam_region *mr_tcam_region)
{
	struct mlxsw_sp *mlxsw_sp = mr_tcam_region->mlxsw_sp;
	char rtar_pl[MLXSW_REG_RTAR_LEN];

	mlxsw_reg_rtar_pack(rtar_pl, MLXSW_REG_RTAR_OP_ALLOCATE,
			    mr_tcam_region->rtar_key_type,
			    MLXSW_SP_MR_TCAM_REGION_BASE_COUNT);
	return mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(rtar), rtar_pl);
}

static void
mlxsw_sp_mr_tcam_region_free(struct mlxsw_sp_mr_tcam_region *mr_tcam_region)
{
	struct mlxsw_sp *mlxsw_sp = mr_tcam_region->mlxsw_sp;
	char rtar_pl[MLXSW_REG_RTAR_LEN];

	mlxsw_reg_rtar_pack(rtar_pl, MLXSW_REG_RTAR_OP_DEALLOCATE,
			    mr_tcam_region->rtar_key_type, 0);
	mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(rtar), rtar_pl);
}

static int mlxsw_sp_mr_tcam_region_parman_resize(void *priv,
						 unsigned long new_count)
{
	struct mlxsw_sp_mr_tcam_region *mr_tcam_region = priv;
	struct mlxsw_sp *mlxsw_sp = mr_tcam_region->mlxsw_sp;
	char rtar_pl[MLXSW_REG_RTAR_LEN];
	u64 max_tcam_rules;

	max_tcam_rules = MLXSW_CORE_RES_GET(mlxsw_sp->core, ACL_MAX_TCAM_RULES);
	if (new_count > max_tcam_rules)
		return -EINVAL;
	mlxsw_reg_rtar_pack(rtar_pl, MLXSW_REG_RTAR_OP_RESIZE,
			    mr_tcam_region->rtar_key_type, new_count);
	return mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(rtar), rtar_pl);
}

static void mlxsw_sp_mr_tcam_region_parman_move(void *priv,
						unsigned long from_index,
						unsigned long to_index,
						unsigned long count)
{
	struct mlxsw_sp_mr_tcam_region *mr_tcam_region = priv;
	struct mlxsw_sp *mlxsw_sp = mr_tcam_region->mlxsw_sp;
	char rrcr_pl[MLXSW_REG_RRCR_LEN];

	mlxsw_reg_rrcr_pack(rrcr_pl, MLXSW_REG_RRCR_OP_MOVE,
			    from_index, count,
			    mr_tcam_region->rtar_key_type, to_index);
	mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(rrcr), rrcr_pl);
}

static const struct parman_ops mlxsw_sp_mr_tcam_region_parman_ops = {
	.base_count	= MLXSW_SP_MR_TCAM_REGION_BASE_COUNT,
	.resize_step	= MLXSW_SP_MR_TCAM_REGION_RESIZE_STEP,
	.resize		= mlxsw_sp_mr_tcam_region_parman_resize,
	.move		= mlxsw_sp_mr_tcam_region_parman_move,
	.algo		= PARMAN_ALGO_TYPE_LSORT,
};

static int
mlxsw_sp_mr_tcam_region_init(struct mlxsw_sp *mlxsw_sp, u32 max_prio,
			     struct mlxsw_sp_mr_tcam_region *mr_tcam_region,
			     enum mlxsw_reg_rtar_key_type rtar_key_type)
{
	struct parman_prio *parman_prios;
	struct parman *parman;
	int err;
	int i;

	mr_tcam_region->rtar_key_type = rtar_key_type;
	mr_tcam_region->mlxsw_sp = mlxsw_sp;

	err = mlxsw_sp_mr_tcam_region_alloc(mr_tcam_region);
	if (err)
		return err;

	parman = parman_create(&mlxsw_sp_mr_tcam_region_parman_ops,
			       mr_tcam_region);
	if (!parman) {
		err = -ENOMEM;
		goto err_parman_create;
	}
	mr_tcam_region->parman = parman;

	parman_prios = kmalloc_array(max_prio + 1, sizeof(*parman_prios),
				     GFP_KERNEL);
	if (!parman_prios)
		goto err_parman_prios_alloc;
	mr_tcam_region->parman_prios = parman_prios;

	for (i = 0; i < max_prio + 1; i++)
		parman_prio_init(mr_tcam_region->parman,
				 &mr_tcam_region->parman_prios[i], i);
	return 0;

err_parman_prios_alloc:
	parman_destroy(parman);
err_parman_create:
	mlxsw_sp_mr_tcam_region_free(mr_tcam_region);
	return err;
}

static void
mlxsw_sp_mr_tcam_region_fini(u32 max_prio,
			     struct mlxsw_sp_mr_tcam_region *mr_tcam_region)
{
	int i;

	for (i = 0; i < max_prio + 1; i++)
		parman_prio_fini(&mr_tcam_region->parman_prios[i]);
	kfree(mr_tcam_region->parman_prios);
	parman_destroy(mr_tcam_region->parman);
	mlxsw_sp_mr_tcam_region_free(mr_tcam_region);
}

static int mlxsw_sp_mr_tcam_init(struct mlxsw_sp *mlxsw_sp, void *priv,
				 u32 max_prio)
{
	struct mlxsw_sp_mr_tcam *mr_tcam = priv;

	if (!MLXSW_CORE_RES_VALID(mlxsw_sp->core, MC_ERIF_LIST_ENTRIES) ||
	    !MLXSW_CORE_RES_VALID(mlxsw_sp->core, ACL_MAX_TCAM_RULES))
		return -EIO;

	mr_tcam->max_prio = max_prio;
	return mlxsw_sp_mr_tcam_region_init(mlxsw_sp, max_prio,
					    &mr_tcam->ipv4_tcam_region,
					    MLXSW_REG_RTAR_KEY_TYPE_IPV4_MULTICAST);
}

static void mlxsw_sp_mr_tcam_fini(void *priv)
{
	struct mlxsw_sp_mr_tcam *mr_tcam = priv;

	mlxsw_sp_mr_tcam_region_fini(mr_tcam->max_prio,
				     &mr_tcam->ipv4_tcam_region);
}

const struct mlxsw_sp_mr_ops mlxsw_sp_mr_tcam_ops = {
	.priv_size = sizeof(struct mlxsw_sp_mr_tcam),
	.route_priv_size = sizeof(struct mlxsw_sp_mr_tcam_route),
	.init = mlxsw_sp_mr_tcam_init,
	.route_create = mlxsw_sp_mr_tcam_route_create,
	.route_update = mlxsw_sp_mr_tcam_route_update,
	.route_stats = mlxsw_sp_mr_tcam_route_stats,
	.route_action_update = mlxsw_sp_mr_tcam_route_action_update,
	.route_min_mtu_update = mlxsw_sp_mr_tcam_route_min_mtu_update,
	.route_irif_update = mlxsw_sp_mr_tcam_route_irif_update,
	.route_erif_add = mlxsw_sp_mr_tcam_route_erif_add,
	.route_erif_del = mlxsw_sp_mr_tcam_route_erif_del,
	.route_destroy = mlxsw_sp_mr_tcam_route_destroy,
	.fini = mlxsw_sp_mr_tcam_fini,
};
