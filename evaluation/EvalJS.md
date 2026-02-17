## Evaluation for JavaScript Vulnerability Detection

## Baslines for JavaScript Vulnerability Detection

- **FAST**
  + (jsflow is built on top of FAST)
  + S&P 23: Scaling JavaScript Abstract Interpretation to Detect and Exploit Node.js Taint-style Vulnerability. Mingqing Kang, Yichao Xu, Song Li, Rigel Gjomemo, Jianwei Hou, V.N. Venkatakrishnan, and Yinzhi Cao. 
  + https://github.com/fast-sp-2023/fast
- **ODGen**
  + USENIX Security 22: Mining Node.js Vulnerabilities via Object Dependence Graph and Query. Song Li, Mingqing Kang, Jianwei Hou, and Yinzhi Cao.
  + https://github.com/Song-Li/ODGen
- **Graph.js**
  + PLDI 24: Efficient Static Vulnerability Analysis for JavaScript with Multiversion Dependency Graphs. Mafalda Ferreira, Miguel Monteiro, Tiago Brito, Miguel E. Coimbra, Nuno Santos, Limin Jia, and José Fragoso Santos.
  + https://github.com/formalsec/graphjs
  

## Exploit Generation for JavaScript

- **explore-js**
  + PLDI 25: Automated Exploit Generation for Node.js Packages. Filipe Marques, Mafalda Ferreira, André Nascimento, Miguel E. Coimbra, Nuno Santos, Limin Jia, José Fragoso Santos.
  + https://github.com/formalsec/explode-js, https://github.com/formalsec/explodejs-datasets
- **NODEMEDIC-FINE**
  + NDSS 25: NODEMEDIC-FINE: Automatic
Detection and Exploit Synthesis for Node.js Vulnerabilities. Darion Cassel, Nuno Sabino, Min-Chien Hsu, Ruben Martins, and Limin Jia. 
  + https://github.com/NodeMedicAnalysis/NodeMedic-FINE


## Dataset for JavaScript Vulnerability Detection

- **VulcaN**
  + TR 23: Study of JavaScript Static Analysis Tools for Vulnerability Detection in Node.js Packages.  Tiago Brito, Mafalda Ferreira, Miguel Monteiro, Pedro Lopes, Miguel Barros, José Fragoso Santos, and Nuno Santos.
- **SecBench.js**
  + ICSE 23: SecBench.js: An Executable Security Benchmark Suite for Server-Side JavaScript. Masudul Hasan Masud Bhuiyan, Adithya Srinivas Parthasarathy, Nikos Vasilakis, Michael Pradel, and CristianAlexandru Staicu
- "explore.js" (PLDI 25) ("Collected consists of 32,137 popular real-world Node.js packages crawled from the npm repository in September 2023. We consider a package to be popular if it had ≥ 2,000 weekly downloads
at the time of collection. For the collected dataset, there is no ground truth because we did not
manually analyze the source code of the packages to identify exploits")