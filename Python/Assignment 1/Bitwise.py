#bitwise operator are used to perform bitwise calculation.these are applicable only for integer and boolean type only
#if we try to use any  other type then pvm (python virtual machine) gives you error.(boolean is like T=1/F=0) 

# types of Bitwise Operator

# and(&)-if both bits have 1 then result is 1 otherwise 0
a=3      #00000011   
b=2      #00000010  
c=a&b   
print(c)      #output:2(00000010)

#or(|)-if anyone bits have 1 then result is 1 otherwise 0
a=3    #00000011
b=2    #00000010
c=a|b  
print(c)     #output:3(00000011)

#xor(^)- if both bits are different (one is 0 othe is 1) then result is 1 otherwise 0
a=3    #00000011
b=2    #00000010
c=a^b  
print(c)     #output:1(#00000001)

#not(~)- it reverses the bits of operands means if there is 0 it becomes 1 and 1 becomes 0.it operates on singlr operand
a=3           #00000011
print(~a)     #output:-4(11111100)
