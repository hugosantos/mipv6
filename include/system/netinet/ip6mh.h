#ifndef _IP6MH_H_
#define _IP6MH_H_

#include <stdint.h>
#include <netinet/in.h>

/* From
 *   'Extensions to Sockets API for Mobile IPv6'
 *       draft-ietf-mip6-mipext-advapi-07
 */

/* This should go into <netinet/in.h> */
#define IPPROTO_MH	135	/* IPv6 Mobility Header: IANA */

/* This should go into <netinet/ip6.h> */
/* Home Address Destination Option */
struct ip6_opt_home_address {
	uint8_t           ip6oha_type;
	uint8_t           ip6oha_len;
	uint8_t           ip6oha_addr[16];   /* Home Address */
};

#define IP6OPT_HOME_ADDRESS        0xc9    /* 11 0 01001 */

/* Type 2 Routing header for Mobile IPv6 */
struct ip6_rthdr2 {
	uint8_t  ip6r2_nxt;       /* next header */
	uint8_t  ip6r2_len;       /* length : always 2 */
	uint8_t  ip6r2_type;      /* always 2 */
	uint8_t  ip6r2_segleft;   /* segments left: always 1 */
	uint32_t ip6r2_reserved;  /* reserved field */
	struct in6_addr ip6r2_homeaddr;  /* Home Address */
};

#define PACKED __attribute__((packed))

struct ip6_mh {
	uint8_t	  ip6mh_proto;		/* NO_NXTHDR by default */
	uint8_t   ip6mh_hdrlen;		/* Header len in unit of 8 Octets
					   excluding the first 8 Octets */
	uint8_t   ip6mh_type;           /* Type of Mobility Header */
	uint8_t	  ip6mh_reserved;       /* Reserved */
	uint16_t  ip6mh_cksum;          /* Mobility Header Checksum */
	/* Followed by type specific messages */
} PACKED;

struct ip6_mh_binding_request {
	struct ip6_mh	ip6mhbr_mh;
#define ip6mhbr_proto		ip6mhbr_mh.ip6mh_proto
#define ip6mhbr_hdrlen		ip6mhbr_mh.ip6mh_hdrlen
#define ip6mhbr_type		ip6mhbr_mh.ip6mh_type
#define ip6mhbr_cksum		ip6mhbr_mh.ip6mh_cksum
	uint16_t	ip6mhbr_reserved;
	/* Followed by optional Mobility Options */
} PACKED;

struct ip6_mh_home_test_init {
	struct ip6_mh	ip6mhhti_mh;
#define ip6mhhti_proto	ip6mhhti_mh.ip6mh_proto
#define ip6mhhti_hdrlen	ip6mhhti_mh.ip6mh_hdrlen
#define ip6mhhti_type	ip6mhhti_mh.ip6mh_type
#define ip6mhhti_cksum	ip6mhhti_mh.ip6mh_cksum
	uint16_t	ip6mhhti_reserved;
	uint32_t	ip6mhhti_cookie[2]; /* 64 bit Cookie by MN */
	/* Followed by optional Mobility Options */
} PACKED;

struct ip6_mh_careof_test_init {
	struct ip6_mh	ip6mhcti_mh;
#define ip6mhcti_proto	ip6mhcti_mh.ip6mh_proto
#define ip6mhcti_hdrlen	ip6mhcti_mh.ip6mh_hdrlen
#define ip6mhcti_type	ip6mhcti_mh.ip6mh_type
#define ip6mhcti_cksum	ip6mhcti_mh.ip6mh_cksum
	uint16_t	ip6mhcti_reserved;
	uint32_t	ip6mhcti_cookie[2]; /* 64 bit Cookie by MN */
	/* Followed by optional Mobility Options */
} PACKED;

struct ip6_mh_home_test {
	struct ip6_mh	ip6mhht_mh;
#define ip6mhht_proto	ip6mhht_mh.ip6mh_proto
#define ip6mhht_hdrlen	ip6mhht_mh.ip6mh_hdrlen
#define ip6mhht_type	ip6mhht_mh.ip6mh_type
#define ip6mhht_cksum	ip6mhht_mh.ip6mh_cksum
	uint16_t	ip6mhht_nonce_index;
	uint32_t	ip6mhht_cookie[2]; /* Cookie from HOTI msg */
	uint32_t	ip6mhht_keygen[2]; /* 64 Bit key by CN */
	/* Followed by optional Mobility Options */
} PACKED;

struct ip6_mh_careof_test {
	struct ip6_mh	ip6mhct_mh;
#define ip6mhct_proto	ip6mhct_mh.ip6mh_proto
#define ip6mhct_hdrlen	ip6mhct_mh.ip6mh_hdrlen
#define ip6mhct_type	ip6mhct_mh.ip6mh_type
#define ip6mhct_cksum	ip6mhct_mh.ip6mh_cksum
	uint16_t	ip6mhct_nonce_index;
	uint32_t	ip6mhct_cookie[2]; /* Cookie from COTI msg */
	uint32_t	ip6mhct_keygen[2]; /* 64 Bit key by CN */
	/* Followed by optional Mobility Options */
} PACKED;

struct ip6_mh_binding_update {
	struct ip6_mh	ip6mhbu_mh;
#define ip6mhbu_proto	ip6mhbu_mh.ip6mh_proto
#define ip6mhbu_hdrlen	ip6mhbu_mh.ip6mh_hdrlen
#define ip6mhbu_type	ip6mhbu_mh.ip6mh_type
#define ip6mhbu_cksum	ip6mhbu_mh.ip6mh_cksum
	uint16_t	ip6mhbu_seqno;	/* Sequence Number */
	uint16_t	ip6mhbu_flags;
	uint16_t	ip6mhbu_lifetime; /* Time in unit of 4 sec */
	/* Followed by optional Mobility Options */
} PACKED;

/* Binding Update Flags, in network byte-order */
#define IP6_MH_BU_ACK		0x8000 /* Request a binding ack */
#define IP6_MH_BU_HOME		0x4000 /* Home Registration */
#define IP6_MH_BU_LLOCAL	0x2000 /* Link-local compatibility */
#define IP6_MH_BU_KEYM		0x1000 /* Key management mobility */
#define IP6_MH_BU_MAP		0x0800 /* HMIPv6 Map Registration */

struct ip6_mh_binding_ack {
	struct ip6_mh	ip6mhba_mh;
#define ip6mhba_proto	ip6mhba_mh.ip6mh_proto
#define ip6mhba_hdrlen	ip6mhba_mh.ip6mh_hdrlen
#define ip6mhba_type	ip6mhba_mh.ip6mh_type
#define ip6mhba_cksum	ip6mhba_mh.ip6mh_cksum
	uint8_t		ip6mhba_status; /* Status code */
	uint8_t		ip6mhba_flags;
	uint16_t	ip6mhba_seqno;
	uint16_t	ip6mhba_lifetime;
	/* Followed by optional Mobility Options */
} PACKED;

/* Binding Acknowledgement Flags */
#define IP6_MH_BA_KEYM		0x80

struct ip6_mh_binding_error {
	struct ip6_mh	ip6mhbe_mh;
#define ip6mhbe_proto	ip6mhbe_mh.ip6mh_proto
#define ip6mhbe_hdrlen	ip6mhbe_mh.ip6mh_hdrlen
#define ip6mhbe_type	ip6mhbe_mh.ip6mh_type
#define ip6mhbe_cksum	ip6mhbe_mh.ip6mh_cksum
	uint8_t		ip6mhbe_status;	/* Error Status */
	uint8_t		ip6mhbe_reserved;
	struct in6_addr	ip6mhbe_homeaddr;
	/* Followed by optional Mobility Options */
} PACKED;

struct ip6_mh_opt {
	uint8_t		ip6mhopt_type;	/* Option Type */
	uint8_t		ip6mhopt_len;	/* Option Length */
	/* Followed by variable length Option Data in bytes */
} PACKED;

struct ip6_mh_opt_refresh_advice {
	struct ip6_mh_opt	ip6mora_oh;
#define ip6mora_type		ip6mora_oh.ip6mhopt_type
#define ip6mora_len		ip6mora_oh.ip6mhopt_len
	uint16_t	ip6mora_interval; /* Refresh interval in 4 sec */
} PACKED;

struct ip6_mh_opt_altcoa {
	struct ip6_mh_opt	ip6moa_oh;
#define ip6moa_type		ip6moa_oh.ip6mhopt_type
#define ip6moa_len		ip6moa_oh.ip6mhopt_len
	struct in6_addr		ip6moa_addr; /* Alternate CoA */
} PACKED;

struct ip6_mh_opt_nonce_index {
	struct ip6_mh_opt	ip6moni_oh;
#define ip6moni_type		ip6moni_oh.ip6mhopt_type
#define ip6moni_len		ip6moni_oh.ip6mhopt_len
	uint16_t		ip6moni_home_nonce;
	uint16_t		ip6moni_coa_nonce;
} PACKED;

struct ip6_mh_opt_auth_data {
	struct ip6_mh_opt	ip6moad_oh;
#define ip6moad_type		ip6moad_oh.ip6mhopt_type
#define ip6moad_len		ip6moad_oh.ip6mhopt_len
	uint8_t			ip6moad_data[12];
} PACKED;

#define IP6_MH_TYPE_BRR       0   /* Binding Refresh Request */
#define IP6_MH_TYPE_HOTI      1   /* HOTI Message   */
#define IP6_MH_TYPE_COTI      2   /* COTI Message  */
#define IP6_MH_TYPE_HOT       3   /* HOT Message   */
#define IP6_MH_TYPE_COT       4   /* COT Message  */
#define IP6_MH_TYPE_BU        5   /* Binding Update */
#define IP6_MH_TYPE_BACK      6   /* Binding ACK */
#define IP6_MH_TYPE_BERROR    7   /* Binding Error */

#define  IP6_MHOPT_PAD1       0x00  /* PAD1 */
#define  IP6_MHOPT_PADN       0x01  /* PADN */
#define  IP6_MHOPT_BREFRESH   0x02  /* Binding Refresh */
#define  IP6_MHOPT_ALTCOA     0x03  /* Alternate COA */
#define  IP6_MHOPT_NONCEID    0x04  /* Nonce Index */
#define  IP6_MHOPT_BAUTH      0x05  /* Binding Auth Data */

#define IP6_MH_BAS_ACCEPTED          0   /* BU accepted */
#define IP6_MH_BAS_PRFX_DISCOV       1   /* Accepted, but prefix
					   discovery Required */
#define IP6_MH_BAS_UNSPECIFIED       128 /* Reason unspecified */
#define IP6_MH_BAS_PROHIBIT          129 /* Administratively
					   prohibited */
#define IP6_MH_BAS_INSUFFICIENT      130 /* Insufficient
					   resources */
#define IP6_MH_BAS_HA_NOT_SUPPORTED  131 /* HA registration not
					   supported */
#define IP6_MH_BAS_NOT_HOME_SUBNET   132  /* Not Home subnet */
#define IP6_MH_BAS_NOT_HA            133  /* Not HA for this
					    mobile node */
#define IP6_MH_BAS_DAD_FAILED        134  /* DAD failed */
#define IP6_MH_BAS_SEQNO_BAD         135  /* Sequence number out
					    of range */
#define IP6_MH_BAS_HOME_NI_EXPIRED   136  /* Expired Home nonce
					    index */
#define IP6_MH_BAS_COA_NI_EXPIRED    137  /* Expired Care-of
					    nonce index */
#define IP6_MH_BAS_NI_EXPIRED        138  /* Expired Nonce
					    Indices */
#define IP6_MH_BAS_REG_NOT_ALLOWED   139  /* Registration type
					    change disallowed */

#define IP6_MH_BES_UNKNOWN_HOA    1 /* Unknown binding for HOA */
#define IP6_MH_BES_UNKNOWN_MH     2 /* Unknown MH Type */

/* From RFC 4283, Mobile Node Identifier Option for MIPv6 */

struct ip6_mh_opt_x_mn_ident {
	struct ip6_mh_opt	ip6moxmi_oh;
#define ip6moxmi_type		ip6moxmi_oh.ip6mhopt_type
#define ip6moxmi_len		ip6moxmi_oh.ip6mhopt_len
	uint8_t			ip6moxmi_subtype;
	/* followed by variable-length identifier */
} PACKED;

#define IP6_MHOPT_X_MN_IDENT		0x08  /* Mobile Node Identifier */
#define IP6_MH_X_MNI_NAI		0x01  /* MN-NAI */

/* Dynamic HA discovery and Mobile Prefix specific
 * ICMPv6 structures and definitions */

#include <netinet/icmp6.h>

#define MIP6_HA_DISCOVERY_REQUEST	144
#define MIP6_HA_DISCOVERY_REPLY		145
#define MIP6_PREFIX_SOLICIT		146
#define MIP6_PREFIX_ADVERT		147

struct mip6_dhaad_req { /* Dynamic HA Address Discovery */
	struct icmp6_hdr mip6_dhreq_hdr;
};

#define mip6_dhreq_type		mip6_dhreq_hdr.icmp6_type
#define mip6_dhreq_code		mip6_dhreq_hdr.icmp6_code
#define mip6_dhreq_cksum	mip6_dhreq_hdr.icmp6_cksum
#define mip6_dhreq_id		mip6_dhreq_hdr.icmp6_data16[0]
#define mip6_dhreq_reserved	mip6_dhreq_hdr.icmp6_data16[1]

struct mip6_dhaad_rep { /* Dynamic HA Address Reply */
	struct icmp6_hdr mip6_dhrep_hdr;
	/* Followed by Home Agent IPv6 addresses */
};

#define mip6_dhrep_type		mip6_dhrep_hdr.icmp6_type
#define mip6_dhrep_code		mip6_dhrep_hdr.icmp6_code
#define mip6_dhrep_cksum	mip6_dhrep_hdr.icmp6_cksum
#define mip6_dhrep_id		mip6_dhrep_hdr.icmp6_data16[0]
#define mip6_dhrep_reserved	mip6_dhrep_hdr.icmp6_data16[1]

struct mip6_prefix_solicit { /* Mobile Prefix Solicitation */
	struct icmp6_hdr mip6_ps_hdr;
};

#define mip6_ps_type		mip6_ps_hdr.icmp6_type
#define mip6_ps_code		mip6_ps_hdr.icmp6_code
#define mip6_ps_cksum		mip6_ps_hdr.icmp6_cksum
#define mip6_ps_id		mip6_ps_hdr.icmp6_data16[0]
#define mip6_ps_reserved	mip6_ps_hdr.icmp6_data16[1]

struct mip6_prefix_advert { /* Mobile Prefix Advertisements */
	struct icmp6_hdr mip6_pa_hdr;
	/* Followed by one or more PI options */
};

#define mip6_pa_type		mip6_pa_hdr.icmp6_type
#define mip6_pa_code		mip6_pa_hdr.icmp6_code
#define mip6_pa_cksum		mip6_pa_hdr.icmp6_cksum
#define mip6_pa_id		mip6_pa_hdr.icmp6_data16[0]
#define mip6_pa_flags_reserved	mip6_pa_hdr.icmp6_data16[1]

/* Mobile Prefix Advertisement Flags in network-byte order */
#define MIP6_PA_FLAG_MANAGED	0x8000
#define MIP6_PA_FLAG_OTHER	0x4000

#undef PACKED

#endif /* _IP6MH_H_ */
