use crate::{chain::Chain, MsgType, ProtoFamily};
use crate::{expr::{self, Expression}};
use crate::expr::meta::Meta;
use crate::expr::payload::{self, Payload};
use nftnl_sys::{self as sys, libc};
use std::ffi::{c_void, CStr, CString};
use std::os::raw::c_char;

/// A nftables firewall rule.
pub struct Rule<'a> {
    rule: *mut sys::nftnl_rule,
    chain: &'a Chain<'a>,
}

// Safety: It should be safe to pass this around and *read* from it
// from multiple threads
unsafe impl<'a> Send for Rule<'a> {}
unsafe impl<'a> Sync for Rule<'a> {}

impl<'a> Rule<'a> {
    /// Creates a new rule object in the given [`Chain`].
    ///
    /// [`Chain`]: struct.Chain.html
    pub fn new(chain: &'a Chain<'_>) -> Rule<'a> {
        unsafe {
            let rule = try_alloc!(sys::nftnl_rule_alloc());
            sys::nftnl_rule_set_u32(
                rule,
                sys::NFTNL_RULE_FAMILY as u16,
                chain.get_table().get_family() as u32,
            );
            sys::nftnl_rule_set_str(
                rule,
                sys::NFTNL_RULE_TABLE as u16,
                chain.get_table().get_name().as_ptr(),
            );
            sys::nftnl_rule_set_str(
                rule,
                sys::NFTNL_RULE_CHAIN as u16,
                chain.get_name().as_ptr(),
            );

            Rule { rule, chain }
        }
    }

    /// Sets the position of this rule within the chain it lives in. By default a new rule is added
    /// to the end of the chain.
    pub fn set_position(&mut self, position: u64) {
        unsafe {
            sys::nftnl_rule_set_u64(self.rule, sys::NFTNL_RULE_POSITION as u16, position);
        }
    }

    pub fn set_handle(&mut self, handle: u64) {
        unsafe {
            sys::nftnl_rule_set_u64(self.rule, sys::NFTNL_RULE_HANDLE as u16, handle);
        }
    }

    /// Adds an expression to this rule. Expressions are evaluated from first to last added.
    /// As soon as an expression does not match the packet it's being evaluated for, evaluation
    /// stops and the packet is evaluated against the next rule in the chain.
    pub fn add_expr(&mut self, expr: &impl Expression) {
        unsafe { sys::nftnl_rule_add_expr(self.rule, expr.to_expr(self)) }
    }

    /// Returns a reference to the [`Chain`] this rule lives in.
    ///
    /// [`Chain`]: struct.Chain.html
    pub fn get_chain(&self) -> &Chain<'_> {
        self.chain
    }
}

unsafe impl<'a> crate::NlMsg for Rule<'a> {
    unsafe fn write(&self, buf: *mut c_void, seq: u32, msg_type: MsgType) {
        let type_ = match msg_type {
            MsgType::Add => libc::NFT_MSG_NEWRULE,
            MsgType::Del => libc::NFT_MSG_DELRULE,
        };
        let flags: u16 = match msg_type {
            MsgType::Add => (libc::NLM_F_CREATE | libc::NLM_F_APPEND | libc::NLM_F_EXCL) as u16,
            MsgType::Del => 0u16,
        };
        let header = sys::nftnl_nlmsg_build_hdr(
            buf as *mut c_char,
            type_ as u16,
            self.chain.get_table().get_family() as u16,
            flags,
            seq,
        );
        sys::nftnl_rule_nlmsg_build_payload(header, self.rule);
    }
}

impl<'a> Drop for Rule<'a> {
    fn drop(&mut self) {
        unsafe { sys::nftnl_rule_free(self.rule) };
    }
}

pub fn get_rules_nlmsg(seq: u32) -> Vec<u8> {
    let mut buffer = vec![0; crate::nft_nlmsg_maxsize() as usize];
    unsafe {
        let header = sys::nftnl_nlmsg_build_hdr(
            buffer.as_mut_ptr() as *mut c_char,
            libc::NFT_MSG_GETRULE as u16,
            ProtoFamily::Unspec as u16,
            libc::NLM_F_DUMP as u16,
            seq,
        );

        let rule = try_alloc!(sys::nftnl_rule_alloc());

        let rule_table = CString::new("diplonat").unwrap();
        let rule_chain = CString::new("input").unwrap();

        sys::nftnl_rule_set_str(
          rule,
          sys::NFTNL_RULE_TABLE as u16,
          rule_table.as_ptr(),
        );
        sys::nftnl_rule_set_str(
          rule,
          sys::NFTNL_RULE_CHAIN as u16,
          rule_chain.as_ptr(),
        );

        sys::nftnl_rule_nlmsg_build_payload(header, rule);        
    };
    buffer
}

extern "C" fn expr_cb(e: *mut sys::nftnl_expr, data: *mut libc::c_void) -> libc::c_int {
  let v: &mut Vec<*mut sys::nftnl_expr> = unsafe { &mut *(data as *mut Vec<*mut sys::nftnl_expr>) };
  v.push(e);
  return 1;
}

fn analyze_meta(expr: (*mut sys::nftnl_expr, *mut sys::nftnl_expr)) -> (Meta, u16) {
  // check l4proto

  let (data, _size) = unsafe {
    let mut size: u32 = 0;
    let d: *const c_void = sys::nftnl_expr_get(
        expr.1,
        sys::NFTNL_EXPR_CMP_DATA as u16,
        &mut size as *mut u32,
    );
  
    (d, size)
  };

  // check data type
  let data = unsafe { *(data as *const u16) };

  (Meta::L4Proto, data)

}

fn analyze_payload(expr: (*mut sys::nftnl_expr, *mut sys::nftnl_expr), l4proto: u16) -> (Payload, u16) {
  let base = unsafe { sys::nftnl_expr_get_u32(expr.0, sys::NFTNL_EXPR_PAYLOAD_BASE as u16) };
  let h = libc::NFT_PAYLOAD_TRANSPORT_HEADER as u32;
  if base == h {

    let (data, _size) = unsafe {
      let mut size: u32 = 0;
      let d: *const c_void = sys::nftnl_expr_get(
          expr.1,
          sys::NFTNL_EXPR_CMP_DATA as u16,
          &mut size as *mut u32,
      );

      (d, size)
    };
  
    // check data type
    let data = unsafe { *(data as *const u16) };
    let data = ((data & 0x00ff) << 8) + ((data & 0xff00) >> 8);

    // we assume tcp or udp here
    let offset  = unsafe { sys::nftnl_expr_get_u32(expr.0, sys::NFTNL_EXPR_PAYLOAD_OFFSET as u16) };    

    let field = match l4proto { 
      6 => {
        if offset == 0 { // sport
          Payload::Transport(payload::TransportHeaderField::Tcp(payload::TcpHeaderField::Sport))
        }
        //if offset == 2 { // dport
        else {
          Payload::Transport(payload::TransportHeaderField::Tcp(payload::TcpHeaderField::Dport)) 
        }
      },

      17 => { // 17 = udp
        if offset == 0 { // sport
          Payload::Transport(payload::TransportHeaderField::Udp(payload::UdpHeaderField::Sport))
        } 
        //if offset == 2 { // dport
        else {
          Payload::Transport(payload::TransportHeaderField::Udp(payload::UdpHeaderField::Dport)) 
        }
      },
  
      _ => panic!("payload proto not supported")
    };

    (field, data)

  } else {
    panic!("payload expr {} not implemented", base);
  }
}

fn analyze_rule(expressions: &Vec<*mut sys::nftnl_expr>) {
  
  let mut l4proto: u16 = 0;
  let typ: u16 = 0;
  let port: u16 = 0;
  let mut i = 0;

  while i < expressions.len() {
    let e_name = unsafe {
         CStr::from_ptr(sys::nftnl_expr_get_str(expressions[i], sys::NFTNL_EXPR_NAME as u16)).to_owned().into_string().unwrap()
    };

    match e_name.as_str() {
      "meta" => {
        if let (Meta::L4Proto, x) = analyze_meta((expressions[i], expressions[i+1])) {
          println!("meta l4proto {}", x);
          l4proto = x;
        }

        i+=2;
      },

      "payload" => {
        println!("{:?}", analyze_payload((expressions[i], expressions[i+1]), l4proto));
        i+=2;
      },
      _ => {
        i+=2;
      } 
    }

  }
 
}

pub fn get_rules_cb(header: &libc::nlmsghdr, _data: &mut Vec<CString>) -> libc::c_int {
  unsafe {
    let rule = try_alloc!(sys::nftnl_rule_alloc());


    let v = vec![0; 4096];
    let buf = CString::from_vec_unchecked(v);
    let p = buf.into_raw();

    let err = sys::nftnl_rule_nlmsg_parse(header, rule);
    if err < 0 {
        error!("Failed to parse nelink table message - {}", err);
        sys::nftnl_rule_free(rule);
        return err;
    }


    let mut v2: Vec<*mut sys::nftnl_expr> = Vec::new();    
    sys::nftnl_expr_foreach(rule, Some(expr_cb), &mut v2 as *mut _ as *mut libc::c_void);
    println!("{:?}", v2);
    //println!("{}", s);

    analyze_rule(&v2);

    sys::nftnl_rule_snprintf(p, 4096, rule, sys::NFTNL_OUTPUT_DEFAULT, 0);
    
    let fr = CString::from_raw(p);
    let s = fr.into_string().unwrap();
    println!("{}", s);

  }

  return 1;
}

