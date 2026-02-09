# TODO
1. ebpf aas program (splitter stuff) [jo hai sahi hai bas explain sahi se karna hai isko]
2. Include lucas' code in the code base or as a git submodule
3. Cross program interference part
    * Either just report what is the interference and stuff.
    * Add support for input of expected dependency
4. add support for return value in the config
5. program load wala support do
6. some internal timeout (fail if not terminate)
7. Config improve kar sakte ?
8. Decide the final constraints and code => after march no change in these values are allowed [towards end of fed]
9. Support for conditional policies [Next Job]

# TODO Priority (before final submission in march)
1, 3, 8, 9


## Plan to implement conditional policy (eval logic)
Conditional constraints

* Ensure that only one level is enough. 

- construct one multilevel policy and see if it makes sense ??
    - is it a policy or sequence of action => policy.
    -  So there is some allowed action at end if that action is done in satisfactory manner then good else also good unless violated.
- can a precondition depend on another precondition
    - PC => A,B 
        Do not write on byte 3 and 4 if you have read the ip address followed by access to map named MAP_IP. (This is possible condition)
- Criteria of passed or not passed ?
    1. List of final conditions and each depend on a tree of precondition where the final condition is the root node.
    2. A -> B : Represend A occur before B
    3. We start from leaves and move up to the root node.
    4. some node evaluates to be false and it is not the root node (final condition) then whole path upto the 1st split is pruned and considered to be false
    5. for nodes just adjacent to the root node if any of them if valid then we check condition with the root node else we dont
    6. verification of that state fails if and only if the root node evaluation is invalid. All the tree traversal is only to know if we need to check the root condition or not.
