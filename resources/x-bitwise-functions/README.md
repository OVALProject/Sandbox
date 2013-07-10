## OVAL Language Sandbox Bitwise Function

Included are the necessary OVAL Language modifications to implement the Bitwise Functions (AND, OR, XOR, NOT).
For validation, make sure to reference the correct x-oval-definitions-schema.xsd schema location in both the definition and results file.

Further documentation is included within the x-oval-definitions-schema.xsd file.

## Implementation of the Bitwise Function
Please checkout the bitwise_function branch of the OVAL interpreter to test out the full implementation. This can be found [here](http://ovaldi.svn.sourceforge.net/viewvc/ovaldi/branches/bitwise_function/), or by using the svn checkout command "svn co https://ovaldi.svn.sourceforge.net/svnroot/ovaldi/branches/bitwise_function/ ovaldi_bitfun".
A copy of the change log for implementation is listed below:

---------------------------------------
--- Version 5.11 build 1, Bitwise ---
---------------------------------------
* Added datatype private field and mutator/accessor functions to AbsComponent and ComponentValue. Updated constructor to match.
* Fixed spelling error in variable in CollectedObject.
* Enhanced StringToLongLong base estimation in Common.cpp.
* Overloaded generic ToString and FromString functions to take an extra output base parameter in Common.h.
* Added "bitwise" as an allowed function grouping in ComponentFactory.
* Implemented the new datatype field in the "Parse" and "ComputeValue" abstracted functions in LiteralComponent, ObjectComponent, and VariableComponent. Fixed comments.
* Added "BitwiseOperation" enum and related functions to OvalEnum.
* Updated VariableProbe to retain datatype when resolving variable references.
