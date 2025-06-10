
/**
 * @name Dependency confusion via custom registry
 * @description Detects custom or untrusted registries in .npmrc files.
 * @kind problem
 * @problem.severity warning
 */

import javascript

from File f
where
  f.getName() = ".npmrc" and
  f.readRawContent().matches(
    "(?m)^\\s*registry\\s*=\\s*(?!https?://(registry\\.npmjs\\.org|npmjs\\.com)).*"
  )
select f, "Potential dependency confusion: custom or untrusted registry in .npmrc."
