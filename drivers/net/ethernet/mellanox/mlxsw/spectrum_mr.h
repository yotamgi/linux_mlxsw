/*
 * drivers/net/ethernet/mellanox/mlxsw/spectrum_mr.h
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

#ifndef _MLXSW_SPECTRUM_MCROUTER_H
#define _MLXSW_SPECTRUM_MCROUTER_H

#include "spectrum.h"

enum mlxsw_sp_mr_route_action {
	MLXSW_SP_MR_ROUTE_ACTION_FORWARD,
	MLXSW_SP_MR_ROUTE_ACTION_TRAP,
	MLXSW_SP_MR_ROUTE_ACTION_TRAP_AND_FORWARD,
};

enum mlxsw_sp_mr_route_prio {
	MLXSW_SP_MR_ROUTE_PRIO_SG,
	MLXSW_SP_MR_ROUTE_PRIO_STARG,
	MLXSW_SP_MR_ROUTE_PRIO_CATCHALL,

};

struct mlxsw_sp_mr_ops {

	int priv_size;
	int route_priv_size;

	int init(struct mlxsw_sp *mlxsw_sp, void *priv);

	int (*route_create)(struct mlxsw_sp *mlxsw_sp, void *priv,
			    void *route_priv, int prio, int vrid,
			    __be32 group, __be32 group_mask,
			    __be32 source, __be32 source_mask,
			    u16 irif_index, u16 *erif_indices,
			    size_t erif_num, u16 min_ttl, u16 min_mtu,
			    enum mlxsw_sp_mr_route_action route_action)

	int (*route_stats)(struct mlxsw_sp *mlxsw_sp, void *route_priv,
			   u64 *packets, u64 *bytes)

	int (*route_action_update)(struct mlxsw_sp *mlxsw_sp, void *route_priv,
				   enum mlxsw_sp_mr_route_action route_action);

	int (*route_min_mtu_update)(struct mlxsw_sp *mlxsw_sp, void *route_priv,
				    u16 min_mtu);

	int (*route_erif_add)(struct mlxsw_sp *mlxsw_sp, void *route_priv,
			      u16 erif_index);

	int (*route_erif_del)(struct mlxsw_sp *mlxsw_sp, void *route_priv,
			      u16 erif_index);

	void (*route_destroy)(struct mlxsw_sp *mlxsw_sp, void *route_priv)

	void fini(void *priv);
};

struct mlxsw_sp_mr {
	struct mlxsw_sp_mr_ops *mr_ops;
	void *catchall_route_priv;
	unsigned long priv[0];
	/* priv has to be always the last item */
};

int mlxsw_sp_mr_init(struct mlxsw_sp *mlxsw_sp,
		     struct mlxsw_sp_mr_ops *mlxsw_sp_mr_ops);

#endif
