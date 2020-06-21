// Qtum offline staking contract v0.1

pragma solidity ^0.5.11;

contract Delegations{

	event AddDelegation(
		address indexed _staker,
		address indexed _delegate,
		uint8 fee,
		uint blockHeight,
		bytes PoD
		);

	event RemoveDelegation(
		address indexed _staker,
		address indexed _delegate
		);

	struct delegation{
		address staker;
		uint8 fee;
		uint blockHeight;
		bytes PoD; //Proof Of Delegation
	}

	mapping(address=>delegation) public delegations;

	uint256 private dummy; // dummy storage for computationally cheap gas consumption

	function addDelegation(address _staker, uint8 _fee, bytes memory _PoD) public{
		if(_staker==msg.sender) revert("Cannot delegate to self");
		if(_staker==address(0x0)) revert("Invalid staker address");
		if(_fee>100) revert("Invalid fee % (must be an integer between 0 and 100)");
		if(_PoD.length!=65) revert("PoD invalid size, should be 65 bytes");
		if(!verifyPoD(_PoD,_staker,msg.sender)) revert("Invalid PoD signature");
		// Reject already existing delegations
		if(delegations[msg.sender].staker==_staker && 
		delegations[msg.sender].fee==_fee &&
		keccak256(abi.encodePacked(delegations[msg.sender].PoD))==keccak256(abi.encodePacked(_PoD))
		) revert("Delegation already exists");

		//If this is an update to the staker emit the removal event for the old staker
		if(delegations[msg.sender].blockHeight!=0 && delegations[msg.sender].staker!=_staker){
			emit RemoveDelegation(
				delegations[msg.sender].staker,
				msg.sender
				);
		}
		
		//Emit the new delegation info for the staker
		emit AddDelegation(
			_staker,
			msg.sender,
			_fee,
			block.number,
			_PoD
			);
		
		//Update delegation info
		delegations[msg.sender].staker=_staker;
		delegations[msg.sender].fee=_fee;
		delegations[msg.sender].blockHeight=block.number;
		delegations[msg.sender].PoD=_PoD;

		// we need to make this function call expensive to avoid spam, so here we consume ~2M gas that will go to miners
		if(gasleft()<0x1E9480) revert("Not enough gas left to consume, the recommended gas limit to call this function is 2,250,000");
		uint gas=gasleft();
		while(true) {
			dummy=0x0;
			if(gas-gasleft()>=0x1E8480)break;
		}

	}

	function removeDelegation() public{
		if(delegations[msg.sender].blockHeight==0) revert("Delegation does not exist, so it cannot be removed");
		emit RemoveDelegation(
				delegations[msg.sender].staker,
				msg.sender
				);
		delete delegations[msg.sender];
	}

	function verifyPoD(bytes memory _PoD, address _staker, address _delegate) internal view returns (bool){

		bytes memory prefix = "\x15Qtum Signed Message:\n\x28";
		bytes memory message = toASCIIString(_staker);

		uint8 v = toUint8(slice(_PoD,0,1),0);
		bytes32 r = toBytes32(slice(_PoD,1,32),0);
		bytes32 s = toBytes32(slice(_PoD,33,32),0);

		bytes32 hash = sha256(abi.encodePacked(sha256(abi.encodePacked(prefix,message))));

		return btc_ecrecover(hash,v,r,s)==_delegate;

	}

	function btc_ecrecover(bytes32 msgh, uint8 v, bytes32 r, bytes32 s) internal view returns(address)
    {
        uint256[4] memory input;
        input[0] = uint256(msgh);
        input[1] = v;
        input[2] = uint256(r);
        input[3] = uint256(s);
        uint256[1] memory retval;

        assembly
        {
            if iszero(staticcall(not(0), 0x85, input, 0x80, retval, 32)) {
                revert(0, 0)
            }
        }

        return address(retval[0]);
    }

    function slice(bytes memory _bytes, uint _start, uint _length) internal pure returns (bytes memory)
    {
        require(_bytes.length >= (_start + _length));

        bytes memory tempBytes;

        assembly {
            switch iszero(_length)
            case 0 {
                tempBytes := mload(0x40)
                let lengthmod := and(_length, 31)
                let mc := add(add(tempBytes, lengthmod), mul(0x20, iszero(lengthmod)))
                let end := add(mc, _length)

                for {
                    let cc := add(add(add(_bytes, lengthmod), mul(0x20, iszero(lengthmod))), _start)
                } lt(mc, end) {
                    mc := add(mc, 0x20)
                    cc := add(cc, 0x20)
                } {
                    mstore(mc, mload(cc))
                }

                mstore(tempBytes, _length)
                mstore(0x40, and(add(mc, 31), not(31)))
            }
            default {
                tempBytes := mload(0x40)

                mstore(0x40, add(tempBytes, 0x20))
            }
        }

        return tempBytes;
    }
	
	function toUint8(bytes memory _bytes, uint _start) internal pure returns (uint8) {
        require(_bytes.length >= (_start + 1));
        uint8 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x1), _start))
        }

        return tempUint;
    }

    function toBytes32(bytes memory _bytes, uint _start) internal pure returns (bytes32) {
        require(_bytes.length >= (_start + 32));
        bytes32 tempBytes32;

        assembly {
            tempBytes32 := mload(add(add(_bytes, 0x20), _start))
        }

        return tempBytes32;
    }

    function toASCIIString(address _address) internal pure returns (bytes memory) {
	 	bytes32 _bytes = bytes32(uint256(_address));
	    bytes memory HEX = "0123456789abcdef";
	    bytes memory _string = new bytes(40);
	    for(uint i = 0; i < 20; i++) {
	        _string[i*2] = HEX[uint8(_bytes[i + 12] >> 4)];
	        _string[1+i*2] = HEX[uint8(_bytes[i + 12] & 0x0f)];
	    }
	    return abi.encodePacked(_string);
	}

	}