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

struct mlxsw_sp_mr_tcam {
	struct parman *parman;
	struct parman_prio *parman_prios;
	u32 max_priority;
};

struct mlxsw_sp_mr_rigr2_entry {
	struct list_head list;
	u32 kvdl_index;
	int num_erifs;
	u16 erif_indices[MLXSW_REG_RIGR2_MAX_ERIFS];
	bool synched;
};

struct mlxsw_sp_mr_erif_list {
	struct list_head rigr2_entries;
};

static void mlxsw_sp_mr_erif_list_init(struct mlxsw_sp_mr_erif_list *erif_list)
{
	LIST_HEAD_INIT(erif_list->rigr2_entries);
}

static bool
mlxsw_sp_mr_rigr2_entry_full(struct mlxsw_sp_mr_rigr2_entry *rigr2_entry)
{
	return rigr2_entry->num_erifs == MLXSW_REG_RIGR2_MAX_ERIFS;
}

#define MLXSW_SP_KVDL_RIGR2_SIZE 1

static bool mlxsw_sp_mr_erif_list_empty(struct mlxsw_sp_mr_erif_list *erif_list)
{
	return list_empty(&erif_list->rigr2_entries)
}

static u32
mlxsw_sp_mr_erif_list_kvdl_index(struct mlxsw_sp_mr_erif_list *erif_list)
{
	ASSERT(!mlxsw_sp_mr_erif_list_empty(erif_list));
	return list_first_entry(&erif_list->rigr2_entries)->kvdl_index;
}

static struct mlxsw_sp_mr_rigr2_entry *
mlxsw_sp_mr_rigr2_entry_create(struct mlxsw_sp *mlxsw_sp,
			       struct mlxsw_sp_mr_erif_list *erif_list)
{
	struct mlxsw_sp_mr_rigr2_entry *rigr2_entry;

	rigr2_entry = kzalloc(sizeof(*rigr2_entries), GFP_KERNEL);
	if (!rigr2_entry)
		return ERR_PTR(-ENOMEM);
	err = mlxsw_sp_kvdl_alloc(mlxsw_sp, MLXSW_SP_KVDL_RIGR2_SIZE,
				  &rigr2_entries->kvdl_index)
	if (err) {
		kfree(rigr2_entry);
		return ERR_PTR(err);
	}

	list_add_tail(&erif_list->rigr2_entries, &rigr2_entry->list);
	return rigr2_entry;
}

static void
mlxsw_sp_mr_rigr2_entry_destroy(struct mlxsw_sp *mlxsw_sp,
				struct mlxsw_sp_mr_rigr2_entry *rigr2_entry)
{
	list_del(&rigr2_entry->list);
	mlxsw_sp_kvdl_free(mlxsw_sp, rigr2_entries->kvdl_index)
	kfree(rigr2_entry);
}

static int mlxsw_sp_mr_erif_list_add(struct mlxsw_sp *mlxsw_sp,
				     struct mlxsw_sp_mr_erif_list *erif_list,
				     u16 erif_index)
{
	struct mlxsw_sp_mr_rigr2_entry *last_entry;

	/* if either there is no erif_entry or the last one is full, allocate a
	 * new one
	 */
	if (list_empty(erif_list->rigr2_entries)) {
		last_entry = mlxsw_sp_mr_rigr2_entry_create(mlxsw_sp,
							    erif_list);
		if (IS_ERR(last_entry)
			return PTR_ERR(last_entry);
	} else {
		last_entry = list_last_entry(&erif_list->rigr2_entries);
		if (mlxsw_sp_mr_rigr2_entry_full(last_entry)) {
			last_entry->synched = false;
			last_entry = mlxsw_sp_mr_rigr2_entry_create(mlxsw_sp,
								    erif_list);
			if (IS_ERR(last_entry)
				return PTR_ERR(last_entry);
		}
	}

	/* Add the erif to the last entrie's last index */
	last_entry->erif_indices[last_entry->num_erifs++] = erif_index;
	return 0;
}

static void mlxsw_sp_mr_erif_list_flush(struct mlxsw_sp_mr_erif_list *erif_list)
{
	struct mlxsw_sp_mr_rigr2_entry *rigr2_entry, *tmp;

	list_for_each_entry_safe(rigr2_entry, tmp, erif_list, list)
		mlxsw_sp_mr_rigr2_entry_destroy(rigr2_entry);
}

static int mlxsw_sp_mr_erif_list_commit(struct mlxsw_sp *mlxsw_sp,
					struct mlxsw_sp_mr_erif_list *erif_list)
{
	struct mlxsw_sp_mr_rigr2_entry *rigr2_entry;
	char rigr2_pl[MLXSW_REG_RIGR2_LEN];
	bool first = true;
	int i;

	list_for_each_entry(rigr2_entry, erif_list->rigr2_entries, list) {
		if (rigr2_entry->synched)
			continue;

		if (!first) {
			int next = rigr2_entry->kvdl_index;

			mlxsw_reg_rigr2_vnext_set(rigr2_pl, 1);
			mlxsw_reg_rigr2_next_rigr_index_set(rigr2_pl, next);
			err = mlxsw_reg_write(mlxsw_sp, MLXSW_REG(rigr2),
					      rigr2_pl);
			if (err)
				/* no need of a rollback here because this
				 * hardware entry should not be pointed yet
				 */
				return err;
		}
		MLXSW_REG_ZERO(ptys, payload);
		mlxsw_reg_rigr2_rigr_index_set(rigr2_pl,
					       rigr2_entry->kvdl_index);
		rigr2_entry->synched = true;
		for (i = 0; i < rigr2_entry->num_erifs; i++) {
			u16 erif = rigr2_entry->erif_indices[i];

			mlxsw_reg_rigr2_erif_entry_v_set(rigr2_pl, i, 1);
			mlxsw_reg_rigr2_erif_entry_erif_set(rigr2_pl, i, erif);
		}
		first = false;
	}

	err = mlxsw_reg_write(mlxsw_sp,  MLXSW_REG(rigr2), rigr2_pl);
	if (err)
		/* no need of a rollback here because this hardware entry should
		 * not be pointed yet
		 */
		return err;
	return 0;
}

struct mlxsw_sp_mr_tcam_route {
	struct mlxsw_sp_mr_erif_list erif_list;
	struct mlxsw_afa_block *afa_block;
	u32 counter_index;
	struct parman_item parman_item;
	int vrid;
	enum mlxsw_sp_mr_route_action action,
	__be32 group;
	__be32 group_mask;
	__be32 source;
	__be32 source_mask;
	u16 irif_index;
	u16 min_ttl;
	u16 min_mtu;
};

static struct mlxsw_afa_block *
mlxsw_sp_mr_tcam_afa_block_create(struct mlxsw_sp *mlxsw_sp,
				  enum mlxsw_sp_mr_route_action route_action,
				  u16 irif_index, u32 counter_index,
				  u16 min_mtu, u16 min_ttl,
				  struct mlxsw_sp_mr_erif_list *erif_list)
{
	struct mlxsw_afa_block *afa_block;
	u32 erif_list_kvdl_index;
	int err;

	afa_block = mlxsw_afa_block_create(mlxsw_sp->afa);
	if (IS_ERR(afa_block))
		return afa_block;

	err = mlxsw_afa_block_append_counter(afa_block, counter_index);
	if (err)
		goto err;

	/* if the action is trap, add one trap action and return */
	if (route_action == MLXSW_SP_MR_ROUTE_ACTION_TRAP) {
		err = mlxsw_afa_block_append_trap(block);
		if (err)
			goto err;
		return block;
	}

	/* if the action is trap and forward, add trap_and_forward action */
	if (route_action == MLXSW_SP_MR_ROUTE_ACTION_TRAP_AND_FORWARD) {
		err = mlxsw_afa_block_append_trap_anf_forward(block);
		if (err)
			goto err;
	}

	erif_list_kvdl_index = mlxsw_sp_mr_erif_list_kvdl_index(erif_list);
	err = mlxsw_afa_block_append_mcrouter(afa_block, irif_index, min_mtu,
					      false, erif_list_kvdl_index);
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

int mlxsw_sp_mr_tcam_route_write(struct mlxsw_sp *mlxsw_sp, int vrid,
				 struct parman_item *parman_item, __be32 group,
				 __be32 group_mask, __be32 source,
				 __be32 source_mask,
				 struct mlxsw_afa_block *afa_block)
{
	char rmft2_pl[MLXSW_REG_RMFT2_LEN];

	mlxsw_reg_rmft2_pack(rmft2_pl, true, parman_item->index, vrid,
			     MLXSW_REG_RMFT2_IRIF_MASK_IGNORE, 0, group,
			     group_mask, source, source_mask,
			     mlxsw_afa_block_first_set(afa_block));

	return mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(rmft2), rmft2_pl);
}

int mlxsw_sp_mr_tcam_route_remove(struct mlxsw_sp *mlxsw_sp, int vrid,
				  struct parman_item *parman_item);
{
	char rmft2_pl[MLXSW_REG_RMFT2_LEN];

	mlxsw_reg_rmft2_pack(rmft2_pl, false, parman_item->index, vrid,
			     0, 0, 0, 0, 0, 0, NULL);

	return mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(rmft2), rmft2_pl);
}

int mlxsw_sp_mr_tcam_route_create(struct mlxsw_sp *mlxsw_sp, void *priv,
				  void *route_priv, int prio, int vrid,
				  __be32 group, __be32 group_mask,
				  __be32 source, __be32 source_mask,
				  u16 irif_index, u16 *erif_indices,
				  size_t erif_num, u16 min_ttl, u16 min_mtu,
				  enum mlxsw_sp_mr_route_action route_action)
{
	struct mlxsw_sp_mr_tcam_route *route = route_priv;
	struct mlxsw_sp_mr_tcam *mlxsw_sp_mr_tcam = priv;
	int err;

	route->vrid = vrid;
	route->group = group;
	route->group_mask = group_mask;
	route->source = source;
	route->source_mask = source_mask;
	route->irif_index = irif_index;
	route->min_ttl = min_ttl;
	route->min_mtu = min_mtu;
	route->action = route_action;

	/* create the egress rifs list */
	mlxsw_sp_mr_erif_list_init(&route->erif_list);
	for (i = 0; i < erif_num; i++) {
		err = mlxsw_sp_mr_erif_list_add(mlxsw_sp, &route->erif_list,
						erif_indices[i]);
		if (err)
			return err_erif_list_add;
	}
	err = mlxsw_sp_mr_erif_list_commit(mlxsw_sp, &route->erif_list);
	if (err)
		goto err_erif_list_commit;

	/* create the flow counter */
	err = mlxsw_sp_flow_counter_alloc(mlxsw_sp, &route->counter_index);
	if (err)
		goto err_flow_counter_alloc;

	/* create the flexible action block */
	route->afa_block = mlxsw_sp_mr_tcam_afa_block_create(mlxsw_sp,
							     route_action,
							     irif_index,
							     min_mtu, min_ttl,
							     &route->erif_list);
	if (IS_ERR(route->afa_block)) {
		err = PTR_ERR(route->afa_block);
		goto err_afa_block_create;
	}

	/* allocate place in the TCAM */
	err = parman_item_add(mlxsw_sp_mr_tcam->parman,
			      &mlxsw_sp_mr_tcam->parman_prios[prio],
			      &route->parman_item);
	if (err)
		goto err_parman_item_add;

	/* write the route to the TCAM */
	err = mlxsw_sp_mr_tcam_route_write(mlxsw_sp, vrid, &route->parman_item,
					   group, group_mask, source,
					   source_mask, route->afa_block);
	if (err)
		goto err_route_write;
	return 0;

err_route_write:
	parman_item_del(route->parman_item)
err_parman_item_add:
	mlxsw_sp_mr_tcam_afa_block_destroy(route->afa_block);
err_afa_block_create:
	mlxsw_sp_flow_counter_free(mlxsw_sp, counter_index);
err_flow_counter_alloc:
err_erif_list_commit:
err_erif_list_add:
	mlxsw_sp_mr_erif_list_flush(mlxsw_sp, &route->erif_list);
	return err;
}

void mlxsw_sp_mr_tcam_route_destroy(struct mlxsw_sp *mlxsw_sp, void *route_priv)
{
	struct mlxsw_sp_mr_tcam_route *route = route_priv;

	mlxsw_sp_mr_tcam_route_remove(mlxsw_sp, route->vrid,
				      &route->parman_item);
	parman_item_del(route->parman_item)
	mlxsw_sp_mr_tcam_afa_block_destroy(route->afa_block);
	mlxsw_sp_flow_counter_free(mlxsw_sp, counter_index);
	mlxsw_sp_mr_erif_list_flush(mlxsw_sp, &route->erif_list);
}

int mlxsw_sp_mr_tcam_route_stats(struct mlxsw_sp *mlxsw_sp, void *route_priv,
				 u64 *packets, u64 *bytes)
{
	struct mlxsw_sp_mr_tcam_route *route = route_priv;

	return mlxsw_sp_flow_counter_get(mlxsw_sp, route->counter_index,
					 packets, bytes);
}

int mlxsw_sp_mr_tcam_route_action_update(struct mlxsw_sp *mlxsw_sp,
					 void *route_priv,
					 enum mlxsw_sp_mr_route_action route_action)
{
	struct mlxsw_sp_mr_tcam_route *route = route_priv;
	struct mlxsw_afa_block *afa_block;
	int err;

	/* create a new flexible action block */
	afa_block = mlxsw_sp_mr_tcam_afa_block_create(mlxsw_sp, route_action,
						      route->irif_index,
						      route->min_mtu,
						      route->min_ttl,
						      &route->erif_list);
	if (IS_ERR(afa_block))
		return PTR_ERR(afa_block);

	/* update the TCAM route entry */
	err = mlxsw_sp_mr_tcam_route_write(mlxsw_sp, route->vrid,
					   &route->parman_item,
					   route->group, route->group_mask,
					   route->source, route->source_mask,
					   afa_block);
	if (err) {
		mlxsw_sp_mr_tcam_afa_block_destroy(afa_block);
		return err;
	}

	/* delete the old one */
	mlxsw_sp_mr_tcam_afa_block_destroy(route->afa_block);
	route->afa_block = afa_block;
	route->action = route_action;
	return 0;
}

int mlxsw_sp_mr_tcam_route_min_mtu_update(struct mlxsw_sp *mlxsw_sp,
					  void *route_priv, u16 min_mtu)
{
	struct mlxsw_sp_mr_tcam_route *route = route_priv;
	struct mlxsw_afa_block *afa_block;
	int err;

	/* create a new flexible action block */
	afa_block = mlxsw_sp_mr_tcam_afa_block_create(mlxsw_sp,
						      route->route_action,
						      route->irif_index,
						      min_mtu, route->min_ttl,
						      &route->erif_list);
	if (IS_ERR(afa_block))
		return PTR_ERR(afa_block);

	/* update the TCAM route entry */
	err = mlxsw_sp_mr_tcam_route_write(mlxsw_sp, route->vrid,
					   &route->parman_item,
					   route->group, route->group_mask,
					   route->source, route->source_mask,
					   afa_block);
	if (err) {
		mlxsw_sp_mr_tcam_afa_block_destroy(afa_block);
		return err;
	}

	/* delete the old one */
	mlxsw_sp_mr_tcam_afa_block_destroy(route->afa_block);
	route->afa_block = afa_block;
	route->min_mtu = min_mtu;
	return 0;
}

int mlxsw_sp_mr_tcam_route_erif_add(struct mlxsw_sp *mlxsw_sp, void *route_priv,
				    u16 erif_index)
{
	struct mlxsw_sp_mr_tcam_route *route = route_priv;
	int err;

	err = mlxsw_sp_mr_erif_list_add(mlxsw_sp, route->erif_list, erif);
	if (err)
		return err;
	return mlxsw_sp_mr_erif_list_commit(mlxsw_sp, route->erif_list)
}

int mlxsw_sp_mr_tcam_route_erif_del(struct mlxsw_sp *mlxsw_sp, void *route_priv,
				    u16 erif_index)
{
	struct mlxsw_sp_mr_tcam_route *route = route_priv;
	struct mlxsw_sp_mr_rigr2_entry *rigr2_entry;
	struct mlxsw_sp_mr_erif_list erif_list;
	struct mlxsw_afa_block *afa_block;
	int err;
	int i;

	/* create a copy of the original erif list without the deleted entry */
	mlxsw_sp_mr_erif_list_init(&erif_list);
	list_for_each_entry(rigr2_entry, &route->erif_list.rigr2_entries, list)
	{
		for (i = 0; i < rigr2_entries->num_erifs; i++) {
			u16 curr_erif = rigr2_entry->erif_indices[i];

			if (curr_erif == erif_index)
				continue;
			err = mlxsw_sp_mr_erif_list_add(mlxsw_sp, &erif_list,
							curr_erif;
			if (err)
				goto err_erif_list_add;
		}
	}
	err = mlxsw_sp_mr_erif_list_commit(mlxsw_sp, &erif_list);
	if (err)
		goto err_erif_list_commit;

	/* create the flexible action block pointing to the new erif list */
	afa_block = mlxsw_sp_mr_tcam_afa_block_create(mlxsw_sp, route->action,
						      route->irif_index,
						      route->min_mtu,
						      route->min_ttl,
						      &erif_list);
	if (IS_ERR(route->afa_block)) {
		err = PTR_ERR(route->afa_block);
		goto err_afa_block_create;
	}

	/* update the TCAM route entry */
	err = mlxsw_sp_mr_tcam_route_write(mlxsw_sp, route->vrid,
					   &route->parman_item, route->group,
					   route->group_mask, route->source,
					   route->source_mask, afa_block);
	if (err)
		goto err_route_write;

	mlxsw_sp_mr_tcam_afa_block_destroy(route->afa_block);
	mlxsw_sp_mr_erif_list_flush(mlxsw_sp, &route->erif_list);
	route->afa_block = afa_block;
	route->erif_list = erif_list;
	return 0;

err_parman_item_add:
	mlxsw_sp_mr_tcam_afa_block_destroy(route->afa_block);
err_afa_block_create:
err_erif_list_commit:
err_erif_list_add:
	mlxsw_sp_mr_erif_list_flush(mlxsw_sp, &route->erif_list);
	return err;
}

#define MLXSW_SP_MR_TCAM_REGION_BASE_COUNT 16
#define MLXSW_SP_MR_TCAM_REGION_RESIZE_STEP 16

static int mlxsw_sp_mr_tcam_region_alloc(struct mlxsw_sp *mlxsw_sp)
{
	char rtar_pl[MLXSW_REG_RTAR_LEN];

	mlxsw_reg_rtar_pack(rtar_pl, MLXSW_REG_RTAR_OP_ALLOCATE,
			    MLXSW_REG_RTAR_KEY_TYPE_IPV4_MULTICAST,
			    MLXSW_SP_MR_TCAM_REGION_BASE_COUNT);
	return mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(rtar), rtar_pl);
}

static void mlxsw_sp_mr_tcam_region_free(struct mlxsw_sp *mlxsw_sp)
{
	char rtar_pl[MLXSW_REG_RTAR_LEN];

	mlxsw_reg_rtar_pack(rtar_pl, MLXSW_REG_RTAR_OP_DEALLOCATE,
			    MLXSW_REG_RTAR_KEY_TYPE_IPV4_MULTICAST, 0);
	return mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(rtar), rtar_pl);
}

static int mlxsw_sp_mr_tcam_region_parman_resize(void *priv,
						 unsigned long new_count)
{
	struct mlxsw_sp *mlxsw_sp = priv;
	char rtar_pl[MLXSW_REG_RTAR_LEN];

	mlxsw_reg_rtar_pack(rtar_pl, MLXSW_REG_RTAR_OP_RESIZE,
			    MLXSW_REG_RTAR_KEY_TYPE_IPV4_MULTICAST, new_count);
	return mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(rtar), rtar_pl);
}

static void mlxsw_sp_mr_tcam_region_parman_move(void *priv,
						unsigned long from_index,
						unsigned long to_index,
						unsigned long count)
{
	struct mlxsw_sp *mlxsw_sp = priv;
	char prcr_pl[MLXSW_REG_PRCR_LEN];

	mlxsw_reg_prcr_pack(prcr_pl, MLXSW_REG_PRCR_OP_MOVE,
			    region->tcam_region_info, src_offset,
			    region->tcam_region_info, dst_offset, size);
	mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(prcr), prcr_pl);
}

static const struct parman_ops mlxsw_sp_mr_tcam_region_parman_ops = {
	.base_count	= MLXSW_SP_MR_TCAM_REGION_BASE_COUNT,
	.resize_step	= MLXSW_SP_MR_TCAM_REGION_RESIZE_STEP,
	.resize		= mlxsw_sp_mr_tcam_region_parman_resize,
	.move		= mlxsw_sp_mr_tcam_region_parman_move,
	.algo		= PARMAN_ALGO_TYPE_LSORT,
};

static int mlxsw_sp_mr_tcam_init(struct mlxsw_sp *mlxsw_sp, void *priv,
				 u32 max_priority)
{
	struct mlxsw_sp_mr_tcam *mlxsw_sp_mr_tcam = priv;
	int err;
	int i;

	err = mlxsw_sp_mr_tcam_region_alloc(mlxsw_sp);
	if (err)
		return err;

	mlxsw_sp_mr_tcam->parman =
		parman_create(&mlxsw_sp_mr_tcam_region_parman_ops, mlxsw_sp);
	if (!mlxsw_sp_mr->parman) {
		err = -ENOMEM;
		goto err_parman_create;
	}

	mlxsw_sp_mr_tcam->parman_prios =
		kmalloc(sizeof(*mlxsw_sp_mr_tcam->parman_prios) * max_priority);
	if (!mlxsw_sp_mr_tcam->parman_prios)
		goto err_parman_prios_alloc;

	mlxsw_sp_mr_tcam->max_priority = max_priority;
	for (i = 0; i < mlxsw_sp_mr_tcam->max_priority; i++)
		parman_prio_init(&mlxsw_sp_mr_tcam->parman_prios[i], i);
	return 0;

err_parman_prios_alloc:
	parman_destroy(mlxsw_sp_mr_tcam->parman);
err_parman_create:
	mlxsw_sp_mr_tcam_region_free(mlxsw_sp);
	return err;
}

static void mlxsw_sp_mr_tcam_fini(struct mlxsw_sp *mlxsw_sp, void *priv)
{
	struct mlxsw_sp_mr_tcam *mlxsw_sp_mr_tcam = priv;
	int i;

	for (i = 0; i < mlxsw_sp_mr_tcam->max_priority; i++)
		parman_prio_fini(&mlxsw_sp_mr_tcam->parman_prios[i]);
	kfree(mlxsw_sp_mr_tcam->parman_prios);
	parman_destroy(mlxsw_sp_mr_tcam->parman);
	mlxsw_sp_mr_tcam_region_free(mlxsw_sp);
}

struct mlxsw_sp_mr_ops mlxsw_sp_mr_tcam_ops = {
	.priv_size = sizeof(struct mlxsw_sp_mr_tcam),
	.route_priv_size = sizeof(struct mlxsw_sp_mr_tcam_route),
	.init = mlxsw_sp_mr_tcam_init,
	.route_create = mlxsw_sp_mr_tcam_route_create,
	.route_stats = mlxsw_sp_mr_tcam_route_stats,
	.route_action_update = mlxsw_sp_mr_tcam_route_action_update,
	.route_min_mtu_update = mlxsw_sp_mr_tcam_route_min_mtu_update,
	.route_erif_add = mlxsw_sp_mr_tcam_route_erif_add,
	.route_erif_del = mlxsw_sp_mr_tcam_route_erif_del,
	.route_destroy = mlxsw_sp_mr_tcam_route_destroy,
	.fini = mlxsw_sp_mr_tcam_fini,
};
