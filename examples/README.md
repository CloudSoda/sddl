# About Examples

Except for `binary`, the other have the same structure as follows:

1. File `from-windows.raw.txt` contains security descriptor contents (obtained by calling `GetSecurityInfo`) from a windows file in three lines:

  a) as produced by `ConvertSecurityDescriptorToStringSecurityDescriptorW`,
  b) the output of a) and then call `ConvertStringSecurityDescriptorToSecurityDescriptorW`, base64 encoded
  c) calling `MakeSelfRelativeSD` without string conversion, base64 encoded

  Note the file is UTF-16LE encoded since it is the output of a windows program

2. File `from-windows.txt` contains the same information but UTF-8 encoded
3. File `parser-output.txt` contains the output of the parser (function `main.go:main()`) when reading lines 2-3 of `from-windows.txt` file
4. File `compare.txt` contains a) the first line of `frim-windows.txt`, b) the contents of `parser-output.txt`; the purpose is for comparision

In case of `binary`, it contains a single raw binary file that can be used to test, by calling `ParseSecurityDescriptor()` function.
