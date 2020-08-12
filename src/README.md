The `CKKSEvaluator` evaluator class contains the public API for homomorphic evaluation, with methods like `rotate_vector_right` and `multiply`. It also contains protected internal versions of these methods, named `rotate_vector_right_internal` and `multiply_internal`.

Users create a concrete evaluator type, e.g., `DepthFinder` or `OpCount`, which each inherit directly from the `CKKSEvaluator` class, and then call the public API functions. The public API functions do some basic tasks like printing the function name when `verbose` is set and validating inputs. They then call the corresponding internal version of the API call, which is defined in the concrete evaluator.

Some evaluators depend on other evaluators. For example, the `Debug` evaluator calls the `Homomorphic` evaluator and the `ScaleEstimator` evaluator. It does *not* inherit from these evaluators; rather it contains pointers to instances. This means that there are multiple copies of the `CKKSEvaluator` "base" class floating around.

The relationship between the evaluators is described below.

            DepthFinder        Plaintext       Homomorphic
                /\                /                /
               /  \              /                /
              /    \            /                /
             /      \          /                /
        Opcount    ScaleEstimator              /
                               \              /
                                \            /
                                 \          /
                                  \        /
                                   \      /
                                     Debug