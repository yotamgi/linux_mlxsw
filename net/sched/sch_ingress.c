/* net/sched/sch_ingress.c - Ingress and clsact qdisc
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     Jamal Hadi Salim 1999
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>

#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>

struct ingress_sched_data {
	struct tcf_block *block;
};

static struct Qdisc *ingress_leaf(struct Qdisc *sch, unsigned long arg)
{
	return NULL;
}

static unsigned long ingress_get(struct Qdisc *sch, u32 classid)
{
	return TC_H_MIN(classid) + 1;
}

static unsigned long ingress_bind_filter(struct Qdisc *sch,
					 unsigned long parent, u32 classid)
{
	return ingress_get(sch, classid);
}

static void ingress_put(struct Qdisc *sch, unsigned long cl)
{
}

static void ingress_walk(struct Qdisc *sch, struct qdisc_walker *walker)
{
}

static struct tcf_block *ingress_tcf_block(struct Qdisc *sch, unsigned long cl)
{
	struct ingress_sched_data *q = qdisc_priv(sch);

	return q->block;
}

static const struct nla_policy ingress_policy[TCA_CLSACT_MAX + 1] = {
	[TCA_CLSACT_INGRESS_BLOCK]	= { .type = NLA_U32 },
};

static int ingress_parse_opt(struct nlattr *opt, u32 *p_ingress_block_index)
{
	struct nlattr *tb[TCA_CLSACT_MAX + 1];
	int err;

	*p_ingress_block_index = 0;

	if (!opt)
		return 0;
	err = nla_parse_nested(tb, TCA_CLSACT_MAX, opt, ingress_policy, NULL);
	if (err)
		return err;

	if (tb[TCA_CLSACT_INGRESS_BLOCK])
		*p_ingress_block_index =
			nla_get_u32(tb[TCA_CLSACT_INGRESS_BLOCK]);
	return 0;
}

static int ingress_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct ingress_sched_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	u32 ingress_block_index;
	int err;

	err = ingress_parse_opt(opt, &ingress_block_index);
	if (err)
		return err;

	err = tcf_block_get_shared(&q->block, qdisc_net(sch),
				   ingress_block_index, &dev->ingress_cl_list);
	if (err)
		return err;

	net_inc_ingress_queue();
	sch->flags |= TCQ_F_CPUSTATS;

	return 0;
}

static void ingress_destroy(struct Qdisc *sch)
{
	struct ingress_sched_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);

	tcf_block_put_shared(q->block, qdisc_net(sch), &dev->ingress_cl_list);
	net_dec_ingress_queue();
}

static int ingress_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct ingress_sched_data *q = qdisc_priv(sch);
	struct nlattr *nest;

	nest = nla_nest_start(skb, TCA_OPTIONS);
	if (nest == NULL)
		goto nla_put_failure;
	if (nla_put_u32(skb, TCA_CLSACT_INGRESS_BLOCK, q->block->index))
		goto nla_put_failure;

	return nla_nest_end(skb, nest);

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
}

static const struct Qdisc_class_ops ingress_class_ops = {
	.leaf		=	ingress_leaf,
	.get		=	ingress_get,
	.put		=	ingress_put,
	.walk		=	ingress_walk,
	.tcf_block	=	ingress_tcf_block,
	.bind_tcf	=	ingress_bind_filter,
	.unbind_tcf	=	ingress_put,
};

static struct Qdisc_ops ingress_qdisc_ops __read_mostly = {
	.cl_ops		=	&ingress_class_ops,
	.id		=	"ingress",
	.priv_size	=	sizeof(struct ingress_sched_data),
	.init		=	ingress_init,
	.destroy	=	ingress_destroy,
	.dump		=	ingress_dump,
	.owner		=	THIS_MODULE,
};

struct clsact_sched_data {
	struct tcf_block *ingress_block;
	struct tcf_block *egress_block;
};

static unsigned long clsact_get(struct Qdisc *sch, u32 classid)
{
	switch (TC_H_MIN(classid)) {
	case TC_H_MIN(TC_H_MIN_INGRESS):
	case TC_H_MIN(TC_H_MIN_EGRESS):
		return TC_H_MIN(classid);
	default:
		return 0;
	}
}

static unsigned long clsact_bind_filter(struct Qdisc *sch,
					unsigned long parent, u32 classid)
{
	return clsact_get(sch, classid);
}

static struct tcf_block *clsact_tcf_block(struct Qdisc *sch, unsigned long cl)
{
	struct clsact_sched_data *q = qdisc_priv(sch);

	switch (cl) {
	case TC_H_MIN(TC_H_MIN_INGRESS):
		return q->ingress_block;
	case TC_H_MIN(TC_H_MIN_EGRESS):
		return q->egress_block;
	default:
		return NULL;
	}
}

static const struct nla_policy clsact_policy[TCA_CLSACT_MAX + 1] = {
	[TCA_CLSACT_INGRESS_BLOCK]	= { .type = NLA_U32 },
	[TCA_CLSACT_EGRESS_BLOCK]	= { .type = NLA_U32 },
};

static int clsact_parse_opt(struct nlattr *opt, u32 *p_ingress_block_index,
			    u32 *p_egress_block_index)
{
	struct nlattr *tb[TCA_CLSACT_MAX + 1];
	int err;

	*p_ingress_block_index = 0;
	*p_egress_block_index = 0;

	if (!opt)
		return 0;
	err = nla_parse_nested(tb, TCA_CLSACT_MAX, opt, clsact_policy, NULL);
	if (err)
		return err;

	if (tb[TCA_CLSACT_INGRESS_BLOCK])
		*p_ingress_block_index =
			nla_get_u32(tb[TCA_CLSACT_INGRESS_BLOCK]);
	if (tb[TCA_CLSACT_EGRESS_BLOCK])
		*p_egress_block_index =
			nla_get_u32(tb[TCA_CLSACT_EGRESS_BLOCK]);
	return 0;
}

static int clsact_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct clsact_sched_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	u32 ingress_block_index;
	u32 egress_block_index;
	int err;

	err = clsact_parse_opt(opt, &ingress_block_index, &egress_block_index);
	if (err)
		return err;

	err = tcf_block_get_shared(&q->ingress_block, qdisc_net(sch),
				   ingress_block_index, &dev->ingress_cl_list);
	if (err)
		return err;

	err = tcf_block_get_shared(&q->egress_block, qdisc_net(sch),
				   egress_block_index, &dev->egress_cl_list);
	if (err)
		return err;

	net_inc_ingress_queue();
	net_inc_egress_queue();

	sch->flags |= TCQ_F_CPUSTATS;

	return 0;
}

static void clsact_destroy(struct Qdisc *sch)
{
	struct clsact_sched_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);

	tcf_block_put_shared(q->egress_block, qdisc_net(sch),
			     &dev->ingress_cl_list);
	tcf_block_put_shared(q->ingress_block, qdisc_net(sch),
			     &dev->egress_cl_list);

	net_dec_ingress_queue();
	net_dec_egress_queue();
}

static int clsact_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct clsact_sched_data *q = qdisc_priv(sch);
	struct nlattr *nest;

	nest = nla_nest_start(skb, TCA_OPTIONS);
	if (!nest)
		goto nla_put_failure;
	if (nla_put_u32(skb, TCA_CLSACT_INGRESS_BLOCK, q->ingress_block->index))
		goto nla_put_failure;
	if (nla_put_u32(skb, TCA_CLSACT_EGRESS_BLOCK, q->egress_block->index))
		goto nla_put_failure;

	return nla_nest_end(skb, nest);

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
}

static const struct Qdisc_class_ops clsact_class_ops = {
	.leaf		=	ingress_leaf,
	.get		=	clsact_get,
	.put		=	ingress_put,
	.walk		=	ingress_walk,
	.tcf_block	=	clsact_tcf_block,
	.bind_tcf	=	clsact_bind_filter,
	.unbind_tcf	=	ingress_put,
};

static struct Qdisc_ops clsact_qdisc_ops __read_mostly = {
	.cl_ops		=	&clsact_class_ops,
	.id		=	"clsact",
	.priv_size	=	sizeof(struct clsact_sched_data),
	.init		=	clsact_init,
	.destroy	=	clsact_destroy,
	.dump		=	clsact_dump,
	.owner		=	THIS_MODULE,
};

static int __init ingress_module_init(void)
{
	int ret;

	ret = register_qdisc(&ingress_qdisc_ops);
	if (!ret) {
		ret = register_qdisc(&clsact_qdisc_ops);
		if (ret)
			unregister_qdisc(&ingress_qdisc_ops);
	}

	return ret;
}

static void __exit ingress_module_exit(void)
{
	unregister_qdisc(&ingress_qdisc_ops);
	unregister_qdisc(&clsact_qdisc_ops);
}

module_init(ingress_module_init);
module_exit(ingress_module_exit);

MODULE_ALIAS("sch_clsact");
MODULE_LICENSE("GPL");
