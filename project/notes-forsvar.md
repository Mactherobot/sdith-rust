# Forsvars noter

- Kat talk about making it work by having the parsing for input shares different in their implementation, due to our marshalling. This shows that our marshalling is a big improvement for code understanding. Shows how difficult aligning with their spec.
- Showcase the CLI- Keygen, signing and verification. List parameters to show. Maybe create a security level calculator for the parameters supplied in custom param files
- Go through the issues of quantum computing, especially shors and grovers
- Mention the coding problems especially SD, go indepth about what coding problems are. Why is it NP-Hard give overview of proof
- Go through the main ideas of going from an MPC to a ZK-PoK(MPCitH) to a Signature algorithm. Maybe mention TCitH
- Then maybe go over the signing algorithm by just telling about the subroutines.
- Then go into the coolest rust features
- Then go into our code and what parts were interesting and optimized
  - The reuse of code by features flags and the use of traits
  - Our testing setup
- Conclusional things
  - Performance measures. and the future work that can be done to further optimize. Look into parallelism and even more specialised SIMD instructions for all data. Look into multiplication lookup vs shift and add.
  - Actual real state of quantum computing is SDitH ever really going to be used? Only if everything else is broken. Contingency plan
  -

## Questions for Diego

- Level of theory for presentation
- Benchmarking Fluctioations and performance, should we redo the stats
- Are we good or are we missing some major parts? Such as deeper security analysis, or more performance optimizations?
- Do you have some dos and donts for the presentation?
- Look into multiplication lookup vs shift and add.
