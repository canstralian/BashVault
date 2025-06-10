
/**
 * @name Backdoor or poisoned model loading
 * @description Flags calls to transformers.from_pretrained that allow remote code execution or skip validation.
 * @kind problem
 * @problem.severity error
 */

import python

from CallExpr call
where
  call.getCallee().getName() = "from_pretrained" and
  (
    (call.getArgument("trust_remote_code") instanceof Literal and
     call.getArgument("trust_remote_code").getValue() = "True")
    or
    (call.getArgument("skip_validation") instanceof Literal and
     call.getArgument("skip_validation").getValue() = "True")
  )
select call, "Model loading call disables signature verification or allows untrusted code execution."
