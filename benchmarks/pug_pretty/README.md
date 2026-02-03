# Pug Template Injection (CVE-2021-21353)

**CVE-2021-21353**: Remote code execution via unsanitized `pretty` option in Pug template engine

## Vulnerability Summary

The Pug template compiler allowed remote code execution if an attacker could control the `pretty` option passed to the compiler. The vulnerability existed in the `visitMixin` and `visitMixinBlock` functions of `pug-code-gen`, where the `pretty` option was directly concatenated into generated JavaScript code without sanitization.

## Affected Code

**Vulnerable Location**: `packages/pug-code-gen/index.js`

In both `visitMixinBlock` and `visitMixin` functions:
```javascript
// Vulnerable - unsanitized concatenation
"pug_indent.push('" + Array(this.indents + 1).join(this.pp) + "');"
```

## Attack Vector

If user input controls the `pretty` option (e.g., via request query parameters), an attacker can inject arbitrary JavaScript:

```javascript
// Vulnerable code
app.get('/', function (req, res) {
  res.render('index', { pretty: req.query.p })
})

// Malicious payload
?p=');process.mainModule.constructor._load('child_process').exec('whoami');_=('
```

This breaks out of the string and executes arbitrary code during template compilation.

## Detection Strategy

Our detector identifies:

1. **Unsanitized concatenation**: `pretty` option directly concatenated into strings without `stringify()`
2. **Vulnerable patterns**: `"pug_indent.push('" + ... + this.pp + ... + "');"`
3. **Missing sanitization**: Lack of `stringify()` or similar escaping function

## Fix

**Fixed in**: pug@3.0.1, pug-code-gen@3.0.2, pug-code-gen@2.0.3

The fix wraps the value with `stringify()` to properly escape it:
```javascript
// Fixed - properly escaped
'pug_indent.push(' + stringify(Array(this.indents + 1).join(this.pp)) + ');'
```

## Versions

- **Vulnerable**: pug@3.0.0 (tag: `pug@3.0.0`)
- **Fixed**: pug@3.0.1 (tag: `pug@3.0.1`)

## References

- [GitHub Advisory GHSA-p493-635q-r6gr](https://github.com/pugjs/pug/security/advisories/GHSA-p493-635q-r6gr)
- [Original Report #3312](https://github.com/pugjs/pug/issues/3312)
- [CVE-2021-21353](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-21353)

## Setup

Clone the vulnerable and fixed versions:

```bash
./clone.sh
```

This creates two directories:
- `pug_vuln/` - pug@3.0.0 (vulnerable)
- `pug_fixed/` - pug@3.0.1 (patched)

## Usage

Run the detector:

```bash
# Check vulnerable version
isa analyze pug_template pug_vuln --legacy

# Check fixed version
isa analyze pug_template pug_fixed --legacy
```

Expected output:
- Vulnerable version: VULNERABLE (detects unsanitized concatenation)
- Fixed version: NOT VULNERABLE (detects proper sanitization)
