# Cycle1
## Description
- Course: CSC842 Security Tool Development
- Developer: Alex Wollman
- Language: Golang
- Scope: File Analysis


## Description
Golang has support for some basic Mach-o file analysis capabilities, but it does not do everything. The goal of this prototype is to add some additional capability using some of the built in Mach-o functionality. In this iteration the primary capability is to parse the Mach-o header and some of the Load Commands, Segments, and Sections, as well as create data types for these things and expose them to the user.

## Capabilities
### Structures
The machoHeader class has 1 primary structure of interest which is comprised of other structures as appropriate. FileHeader contains the machoHeader (which is taken directly from the golang supported library) and the LoadCommand structure which I created. This LoadCommand structure contains another structure called SectionHeader (which I also created) which contains the associated section information for segments, if any exist. All of these structures are accessible from the user's scope.

### Functionality
The primary function exposed is the LoadStruct function which, as the name suggests, loads the FileHeader structure with information from a provided file. The two Print functions (PrintSection and PrintSegment) do as their name suggests as well. There are a few internal functions used to facilitate the printing or population of structures which are not available to the end user for use. 

## Future Work
This is the very minimum amount of information that can be extracted from the binary and its headers and still provide something useful. There are many different segments, sections, and constants that can be identified and programmed into this tool. One setback to the development of this tool was the constant retrieval of constant values or structures from the OS X libraries (made available on the devices) and reference material (the excellent books written by Jonathan Levin.) I discovered at the end of this cycle a possible solution called CGO, which on the surface seems to enable the inclusion of C style headers and code into a golang solution. This would simplify the code base, and also enable a more dynamic tool as every time something changes in the header it would automatically be pulled into the code base.

One less significant change would be to associate the Print functions with the FileHeader structure. Currently they are external to the FileHeader, which does not make sense as they only work with that structure. This would be a minor update, but would require reworking how the functions are called and how the data is stored and passed.

## References
*OS Internals Volume 1 2nd Edition "User Space" by Jonathan Levin, 