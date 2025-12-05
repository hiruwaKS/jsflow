# Research Plan: LLM-Assisted Stub Generation

## Background

Static analysis tools (like jsflow) require stub files for standard and third-party libraries to track data flow and detect security vulnerabilities. Currently, these stubs are written manually, which is time-consuming and error-prone.

## Objective

Use LLMs to automatically generate high-quality stub files for:
- **Standard libraries**: Node.js built-in modules (fs, http, child_process, etc.)
- **Third-party libraries**: Common npm packages (express, mongodb, yargs, etc.)

## Stub File Requirements

Stubs must include data flow markers:

**Source markers** (user input):
- `source_hqbpillvul_*`, `OPGen_TAINTED_VAR_*`, `__OpgTaintedFakeArg()`

**Sink markers** (vulnerability points):
- Command injection: `sink_hqbpillvul_exec`, `sink_hqbpillvul_spawn`
- XSS: `sink_hqbpillvul_http_write`, `sink_hqbpillvul_http_setHeader`
- NoSQL injection: `sink_hqbpillvul_nosql`
- Code execution: `sink_hqbpillvul_eval`
- Path traversal: `sink_hqbpillvul_fs_read`
- Prototype pollution: `sink_hqbpillvul_pp`
- Database operations: `sink_hqbpillvul_db`

**Key principles**:
- Preserve API signatures (function names, parameters, return values)
- Minimize logic (only data flow tracking)
- Handle callbacks correctly
- Maintain module export structure

**Example patterns**:
```javascript
// Simple function
function readFile(pathname, options, cb) {
  var ret = sink_hqbpillvul_fs_read(pathname);
  cb(ret == '123', ret);
  return ret;
}

// Object methods
var request_builtin_object = function(){
  var OPGen_TAINTED_VAR_url = new __OpgTaintedFakeArg();
  this.url = OPGen_TAINTED_VAR_url;
}

// Prototype methods
module.exports.Collection.prototype.insert = function (docs, options, callback){
  sink_hqbpillvul_nosql(docs);
  callback();
}
```

## Innovation Points

Compared to existing work on LLM-generated taint specifications (e.g., CodeQL rules for Java), this work has several key innovations:

### 1. Executable Stubs vs. Declarative Rules
- **Existing work**: Generates declarative taint specifications (e.g., CodeQL `.ql` files) that define sources, sinks, and sanitizers as rules
- **Our approach**: Generates **executable JavaScript stub code** that preserves full API signatures and can be analyzed by symbolic execution engines
- **Benefit**: Stubs integrate seamlessly into the analysis pipeline as drop-in replacements for real libraries

### 2. Inline Data Flow Markers
- **Existing work**: Taint specifications are separate from code, using pattern matching
- **Our approach**: Data flow markers (`source_hqbpillvul_*`, `sink_hqbpillvul_*`) are **embedded directly in the code flow**
- **Benefit**: Enables precise tracking of data flow through stub implementations during symbolic execution

### 3. JavaScript-Specific Challenges
- **Callback handling**: JavaScript's callback-heavy nature requires stubs to properly simulate callback invocations with marked data
- **Prototype chains**: Must handle prototype-based inheritance patterns (e.g., `Collection.prototype.insert`)
- **Dynamic exports**: Support for CommonJS `module.exports` patterns and dynamic property assignment
- **Benefit**: Addresses language-specific patterns that declarative rules struggle with

### 4. Symbolic Execution Integration
- **Existing work**: CodeQL uses pattern-based matching on AST
- **Our approach**: Stubs are analyzed by **symbolic execution**, allowing path-sensitive analysis and constraint solving
- **Benefit**: Can track complex data flow paths that pattern matching might miss

### 5. API Signature Preservation
- **Existing work**: Taint specs focus on identifying sources/sinks, not maintaining API compatibility
- **Our approach**: Stubs must **preserve exact API signatures** (function names, parameters, return values, module structure)
- **Benefit**: Enables analysis of code that calls these APIs without modification

### 6. Hybrid Analysis Approach
- Combines **source code analysis** (AST extraction) with **documentation understanding** (API semantics)
- Maps APIs to vulnerability types automatically
- Generates context-aware stubs based on both structural and semantic information

## Technical Approach

### Hybrid Method (Recommended)

1. **Extract API signatures** from source code using AST analysis
2. **Identify vulnerability types** using API-to-vulnerability mapping
3. **Generate stubs** using LLM with:
   - Official API documentation
   - Existing stub examples
   - Vulnerability type information

**Prompt structure**:
```
Generate stub for {module_name} ({builtin|third_party}).

APIs: {api_list}
Vulnerability types: {vul_types}

Requirements:
- Preserve all API signatures
- Mark user inputs with source_hqbpillvul_*
- Mark vulnerability points with sink_hqbpillvul_*
- Handle callbacks correctly

Examples: {example_stubs}
```

## Implementation Framework

```
Module Analyzer → Vulnerability Mapper → LLM Generator → Validator
```

**Components**:
1. **Module Analyzer**: Parse package.json, extract APIs from docs/source
2. **Vulnerability Mapper**: Map APIs to vulnerability types, identify sinks/sources
3. **LLM Generator**: Build prompts, call LLM, post-process code
4. **Validator**: Syntax check, completeness check, data flow verification

## Validation

- **Completeness**: All public APIs covered, correct signatures
- **Correctness**: Sink/source markers in correct positions
- **Effectiveness**: Compare with manual stubs, test with jsflow analysis

## Key Challenges

1. **API coverage**: Use TypeScript definitions + multiple doc sources
2. **Marker accuracy**: Build mapping rule library, use existing stubs as training data
3. **Callback handling**: Analyze patterns, provide templates
4. **Version compatibility**: Specify versions, maintain version mappings

## Evaluation Metrics

- API coverage rate
- Sink/source marker accuracy
- Generation efficiency vs. manual writing
- Analysis effectiveness (false positive/negative rates)

## Future Work

- Automated stub updates on library changes
- Multi-language support (Python, Java)
- Community-contributed stub library
- Continuous learning from generated stubs

## References

- Existing stubs: `builtin_packages/`
- Vulnerability definitions: `jsflow/vul_func_lists.py`
- Detection rules: `jsflow/vul_checking.py`
