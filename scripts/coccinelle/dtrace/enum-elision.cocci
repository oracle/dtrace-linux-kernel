/// Reduce uses of typedefs of named enums to the name of the enum

virtual patch
virtual context
virtual org
virtual report

@td@
type T;
identifier E;
@@
- typedef enum E
+ enum E
  { ...
- } T;
+ };
@@
type td.T;
identifier td.E;
@@
- T
+ enum E

@@
type td.T;
identifier td.E;
@@
- const T
+ const enum E
