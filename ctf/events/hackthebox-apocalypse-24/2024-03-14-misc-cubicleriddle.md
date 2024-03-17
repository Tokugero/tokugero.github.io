---
layout: post
title: "misc cubicleriddle"
date: 2024-03-14 17:18:49 -0700
categories: ctfs
description: The "Cubicle Riddle" challenge presents a unique endpoint where participants are prompted to solve a riddle involving numbers. By understanding the code structure, including the "check answer" function and the use of bytecode manipulation with `code type`, participants can craft a function that satisfies the challenge criteria.
parent: HackTheBox - Apocalypse '24
grand_parent: CTF Events
event: "hackthebox-apocalypse"
tags:
- "misc"
- "riddles"
- "code manipulation"
- "bytecode"
- "python"
---

## Cubicle Riddle - Miscellaneous Challenge
The "Cubicle Riddle" challenge tasks participants with solving a riddle presented through an endpoint. Responding affirmatively to the riddle prompt yields a numerical puzzle to be deciphered. However, the underlying mechanics of the challenge involve crafting a specific function that operates on a list of numbers to extract the minimum and maximum values.

```sh
___________________________________________________________
> Riddler: 'In arrays deep, where numbers sprawl,
        I lurk unseen, both short and tall.
        Seek me out, in ranks I stand,
        The lowest low, the highest grand.
        
        What am i?'
        
(Answer wisely) > asdf

Format should be like: int_value1,int_value2,int_value3...
Example answer: 1, 25, 121...
```

### Understanding the Code Structure:
Upon inspecting the source code, participants encounter the "check answer" function responsible for validating input responses. The function expects an undefined `answer_func` that operates on a list of numbers and returns a tuple containing the minimum and maximum values. This `answer_func` is generated using the `construct_answer` method, employing bytecode manipulation techniques.
```python
    def check_answer(self, answer: bytes) -> bool:
        _answer_func: types.FunctionType = types.FunctionType( #< Creating a new "FunctionType" object
            self._construct_answer(answer), {}
        )
        return _answer_func(self.num_list) == (min(self.num_list), max(self.num_list)) #< Using function with input, and output needs to equal the results
```

### Crafting the Solution:
By delving into the workings of `code type`, participants can construct a function that meets the challenge criteria. Utilizing compiled bytecode, participants create a function that takes a list of numbers as input and outputs a tuple containing the minimum and maximum values. It's crucial to ensure compatibility with the challenge environment, matching Python version and architecture specifications.
```python
import types
import code

#Set range of min/max, just like Riddler
max_int = 1000
min_int = -1000

#Create our desired function. Mine was much longer than needed as it was the result of breaking it down as far as I could for debugging purposes
def _answer_func(num_list):
    min_int = 1000
    max_int = 0
    for num in num_list:
        if num < min_int:
            min_int = num
        if num > max_int:
            max_int = num 
    return (min_int, max_int)

#Here we try to get the hex code from this function by grabbing the compiled code from the function. This is important as we need the PLT included in the function, and this will get it as part of the byte output.
hexfunction = bytes(_answer_func.__code__.__getattribute__('co_code'))
print(f'Hexfunction: {hexfunction}')

# Here is the output of the resulting function needed to decode into
print(f'Answer: {answer.hex()}')
```
And moving this from hex > decimal> and then comma delimiting with a comma, we have a useable answer

![alt text](../../../assets/images/ctf/events/hackthebox-apocalypse-24/2024-03-14-misc-cubicleriddle.md/2024-03-14-misc-cubicleriddle/image-1.png)

```sh
        
(Answer wisely) > 151, 0, 100, 1, 125, 1, 100, 2, 125, 2, 124, 0, 68, 0, 93, 18, 125, 3, 124, 3, 124, 1, 107, 0, 0, 0, 0, 0, 114, 2, 124, 3, 125, 1, 124, 3, 124, 2, 107, 4, 0, 0, 0, 0, 114, 2, 124, 3, 125, 2, 140, 19, 124, 1, 124, 2, 102, 2, 83, 0

___________________________________________________________

Upon answering the cube's riddle, its parts spin in a      

dazzling display of lights. A resonant voice echoes through

the woods that says... HTB{FAKEFLAG}
```

### Conclusion:
The "Cubicle Riddle" challenge offers a fascinating exploration of bytecode manipulation and code construction techniques in Python. By understanding the intricacies of `code type` and crafting a function to meet specific criteria, participants can successfully navigate the challenge. This experience underscores the importance of delving into the underlying mechanics of code execution to solve complex puzzles effectively.

