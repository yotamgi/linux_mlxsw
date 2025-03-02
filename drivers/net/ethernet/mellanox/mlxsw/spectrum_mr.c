/*
 * drivers/net/ethernet/mellanox/mlxsw/spectrum_mr.c
 * Copyright (c) 2015-2017 Mellanox Technologies. All rights reserved.
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
#include "spectrum_mr.h"

static int mlxsw_sp_mr_rifs_min_mtu(struct mlxsw_sp_rif *rifs, size_t rifs_num)
{
	u16 min_mtu = 0xffff;
	int i;

	for (i = 0; < i < rifs_num; i++)
		min_mtu = min_t(u16, min_mtu, rifs[i]->mtu);
	return min_mtu;
}

int mlxsw_sp_mr_init(struct mlxsw_sp *mlxsw_sp, struct mlxsw_sp_mr_ops *mr_ops)
{
	struct mlxsw_sp_mr *mr;
	int err;

	mr = kzalloc(sizeof(*mr) + mr_ops->priv_size, GFP_KERNEL);
	if (!mr)
		return -ENOMEM;
	mr->mr_ops = mr_ops;
	mlxsw_sp->mr = mr;

	err = mr_ops->init(mlxsw_sp, mr->priv);
	if (err)
		goto err_mr_ops_init;

	/* Add the catchall route */
	mr->catchall_route_priv = kmalloc(mr_ops->route_priv, GFP_KERNEL);
	if (!mr->catchall_route_priv)
		goto err_catchall_route_priv_alloc;
	return 0;

	mr_ops->route_create(mlxsw_sp, mr->priv, mr->catchall_route_priv,
			     MLXSW_SP_MR_ROUTE_PRIO_CATCHALL,

	kfree(mr->catchall_route_priv);
err_catchall_route_priv_alloc:
	mr_ops->fini(mr->priv);
err_mr_ops_init:
	kfree(mr);
	return err;
}
