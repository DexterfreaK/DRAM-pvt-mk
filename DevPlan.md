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

# Brain storming and ideation
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

# Action plan
- Where do we need to handle this things ??
    1. storing the policy and the preconditions in some data structure in the execution state of klee.
    2. apply constraints while applying executing some memory operation
    3. apply constraints for map and helper function stuff
    4. keep the new class of handling in #ifdef and the older one in #ifndef some variable like CONDITIONAL_POLICY
    5. Currently all the final results are reported in combined mannar for all state. in general for both conditional policy we would like to report the current as well as per-state result. report the per state stuff only in case of failure rest is fine.
- how the conditional policy file will look like
    1. it will be a json object where each policy is mapped with some name and have a list of dependency to make the above kind of graph. All the main or base conditions will have empty dependency list. refer other constrains.json in the examples folder.
        C : {
            map: []
            helper: []
            packet/memory: []
            dependency: [c1,c2]
        }
    2. in conditional policy mode we would also like to mention the packet/memory format in offset and size mode. currently if someone passes sourceIp then we internally convert it into hardcoded offset and size, we would now like to expect the offset and size from the user end itself to make it more flexible.
- How to proceed
    1. read and understand the code and handling in klee related to conditional policy
    2. implement the structural parts like naming the function and defining their empty implementation calling them at required places.
    3. covering and uncovering required stuff with ifdef and ifndefs,
    4. creating sample constraints file and adding its parsing.
    5. completing all required stuff so that we can start writing core logic
    6. writing the core logic of implementation
- Guidelines
    1. follow current code style
    2. keep it simple and minimal dont do unnecessary or extra stuff.

    MOST IMPORTANT -> Keep me in loop and as before and after doing all small and big stuff. I will keep guiding.