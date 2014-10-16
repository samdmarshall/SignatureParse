//
//  main.m
//  SignatureParse
//
//  Created by Sam Marshall on 10/15/14.
//  Copyright (c) 2014 Sam Marshall. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <Security/CSCommonPriv.h>

#include "Core.h"


struct blob_location {
	uint32_t thing;
	uint32_t offset;
};

struct Blob {
	uint32_t magic;
	BufferRef data;
	ArrayRef children;
};

typedef struct Blob * Blob_t;

NSInteger ParseMagic(BufferRef data) {
	uint8_t magic[4] = {0};
	memcpy(&magic, &(data->data[0]), sizeof(uint32_t));
	if (magic[0] == 0xfa && magic[1] == 0xde) {
		printf("found magic -- ");
		switch (magic[2]) {
			case 0x0b: {
				printf("generic\n");
				return kSecCodeMagicByte;
			}
			case 0x0c: {
				if (magic[3] == 0x00) {
					printf("single requirement\n");
					return kSecCodeMagicRequirement;
				}
				if (magic[3] == 0x01) {
					printf("requirement set\n");
					return kSecCodeMagicRequirementSet;
				}
				if (magic[3] == 0x02) {
					printf("CodeDirectory\n");
					return kSecCodeMagicCodeDirectory;
				}
				if (magic[3] == 0xc0) {
					printf("single-architecture embedded signature\n");
					return kSecCodeMagicEmbeddedSignature;
				}
				if (magic[3] == 0xc1) {
					printf("detached multi-architecture signature\n");
					return kSecCodeMagicDetachedSignature;
				}
			}
			case 0x71: {
				if (magic[3] == 0x71) {
					printf("entitlement blob\n");
					return kSecCodeMagicEntitlement;
				}
			}
			default: {
				printf("error!\n");
			}
		}
	}
	
	return kSecCodeMagicByte;
}

uint32_t ParseLengthWithOffset(BufferRef data, uint32_t offset) {
	uint32_t length = 0;
	memcpy(&length, &(data->data[offset]), sizeof(uint32_t));
	length = OSSwapHostToBigInt32(length);
	return length;
}

uint32_t ParseLength(BufferRef data) {
	return ParseLengthWithOffset(data, 4);
}

bool BlobHasChildren(Blob_t blob) {
	return (blob->magic == kSecCodeMagicEmbeddedSignature || blob->magic == kSecCodeMagicRequirementSet);
}

uint32_t ChildCountFromBlob(Blob_t blob) {
	uint32_t count = 0;
	memcpy(&count, &(blob->data->data[8]), sizeof(uint32_t));
	count = OSSwapHostToBigInt32(count);
	return count;
}

struct blob_location GetChildAtIndex(Blob_t blob, uint32_t index) {
	struct blob_location loc = {0};
	memcpy(&loc, &(blob->data->data[12+(sizeof(struct blob_location)*index)]), sizeof(struct blob_location));
	loc.thing = OSSwapHostToBigInt32(loc.thing);
	loc.offset = OSSwapHostToBigInt32(loc.offset);
	return loc;
}

uint32_t GetSizeOfChildAtOffset(Blob_t blob, uint32_t offset) {
	uint32_t size = 0;
	memcpy(&size, &(blob->data->data[offset+4]), sizeof(uint32_t));
	size = OSSwapHostToBigInt32(size);
	return size;
}

enum ExprOp {
	opFalse = 0,					// unconditionally false
	opTrue,							// unconditionally true
	opIdent,						// match canonical code [string]
	opAppleAnchor,					// signed by Apple as Apple's product
	opAnchorHash,					// match anchor [cert hash]
	opInfoKeyValue,					// *legacy* - use opInfoKeyField [key; value]
	opAnd,							// binary prefix expr AND expr [expr; expr]
	opOr,							// binary prefix expr OR expr [expr; expr]
	opCDHash,						// match hash of CodeDirectory directly [cd hash]
	opNot,							// logical inverse [expr]
	opInfoKeyField,					// Info.plist key field [string; match suffix]
	opCertField,					// Certificate field [cert index; field name; match suffix]
	opTrustedCert,					// require trust settings to approve one particular cert [cert index]
	opTrustedCerts,					// require trust settings to approve the cert chain
	opCertGeneric,					// Certificate component by OID [cert index; oid; match suffix]
	opAppleGenericAnchor,			// signed by Apple in any capacity
	opEntitlementField,				// entitlement dictionary field [string; match suffix]
	opCertPolicy,					// Certificate policy by OID [cert index; oid; match suffix]
	opNamedAnchor,					// named anchor type
	opNamedCode,					// named subroutine
	exprOpCount						// (total opcode count in use)
};

enum SyntaxLevel {
	slPrimary,		// syntax primary
	slAnd,			// conjunctive
	slOr,			// disjunctive
	slTop			// where we start
};

uint32_t PrintReq(BufferRef data, uint32_t offset, enum SyntaxLevel level) {
	uint32_t req_code = 0;
	memcpy(&req_code, &(data->data[offset]), sizeof(uint32_t));
	req_code = OSSwapHostToBigInt32(req_code);
	uint32_t size = sizeof(uint32_t);
	switch (req_code) {
		case opFalse: {
			printf("never");
			break;
		}
		case opTrue: {
			printf("always");
			break;
		}
		case opIdent: {
			printf("identifier \"");
			uint32_t length = 0;
			memcpy(&length, &(data->data[offset+size]), sizeof(uint32_t));
			length = OSSwapHostToBigInt32(length);
			for (uint32_t index = 0; index < length; index++) {
				printf("%c",data->data[offset+(size*2)+index]);
			}
			printf("\"");
			size += sizeof(uint32_t) + length + (4 - (length % 4));
			break;
		}
		case opAppleAnchor: {
			printf("anchor apple");
			break;
		}
		case opAnchorHash: {
			printf("certificate");
			break;
		}
		case opInfoKeyValue: {
			break;
		}
		case opAnd: {
			if (level < slAnd)
				printf("(");
			size += PrintReq(data, offset+size, slPrimary);
			printf(" and ");
			size += PrintReq(data, offset+size, slPrimary);
			if (level < slAnd)
				printf(")");
			break;
		}
		case opOr: {
			if (level <= slOr)
				printf("(");
			size += PrintReq(data, offset+size, slPrimary);
			printf(" or ");
			size += PrintReq(data, offset+size, slPrimary);
			if (level < slOr)
				printf(")");
			break;
		}
		case opCDHash: {
			printf("cdhash ");
			break;
		}
		case opNot: {
			printf("! ");
			size += PrintReq(data, offset+size, slPrimary);
			break;
		}
		case opInfoKeyField: {
			break;
		}
		case opCertField: {
			printf("certificate");
			uint32_t length = 0;
			size += sizeof(uint32_t);
			memcpy(&length, &(data->data[offset+size]), sizeof(uint32_t));
			length = OSSwapHostToBigInt32(length);
			size += sizeof(uint32_t) + length + (4 - (length % 4));
			size += sizeof(uint32_t);
			memcpy(&length, &(data->data[offset+size]), sizeof(uint32_t));
			length = OSSwapHostToBigInt32(length);
			size += sizeof(uint32_t) + length + (4 - (length % 4));
			break;
		}
		case opTrustedCert: {
			break;
		}
		case opTrustedCerts: {
			break;
		}
		case opCertGeneric: {
			printf("generic");
			uint32_t length = 0;
			size += sizeof(uint32_t);
			memcpy(&length, &(data->data[offset+size]), sizeof(uint32_t));
			length = OSSwapHostToBigInt32(length);
			size += sizeof(uint32_t) + length + (4 - (length % 4));
			size += sizeof(uint32_t);
			break;
		}
		case opAppleGenericAnchor: {
			printf("anchor apple generic");
			break;
		}
		case opEntitlementField: {
			break;
		}
		case opCertPolicy: {
			break;
		}
		case opNamedAnchor: {
			break;
		}
		case opNamedCode: {
			break;
		}
		default: {
			break;
		}
	}
	printf(" ");
	
	return size;
}

void ParseRequirement(Blob_t blob) {
	uint32_t and_level = 0;
	uint32_t or_level = 0;
	uint32_t level = 0;
	uint32_t last_level = 0;
	
	printf("\tRequirement: ");
	BufferRef data = blob->data;
	uint64_t offset = 8;
	while (offset < data->length) {
		offset += PrintReq(data, offset, slTop);
	}
	printf("\n");
}

Blob_t FindBlobs(BufferRef data, uint32_t offset) {
	Blob_t master = calloc(1, sizeof(struct Blob));
	master->magic = ParseMagic(data);
	printf("\tOffset: %i\n",offset);
	uint32_t size = ParseLength(data);
	printf("\tSize: %i\n",size);
	master->data = CreateBufferFromBufferWithRange(data, RangeCreate(0, size));
	master->children = calloc(1, sizeof(struct CoreInternalArray));
	bool result = BlobHasChildren(master);
	if (result) {
		master->children->count = ChildCountFromBlob(master);
		printf("\tChildren: %i\n",master->children->count);
		master->children->items = calloc(master->children->count, sizeof(Pointer));
		for (uint32_t index = 0; index < master->children->count; index++) {
			struct blob_location location = GetChildAtIndex(master, index);
			uint32_t length = GetSizeOfChildAtOffset(master, location.offset);
			Range child_range = RangeCreate(location.offset, length);
			BufferRef child_data = CreateBufferFromBufferWithRange(data, child_range);
			master->children->items[index] = FindBlobs(child_data, location.offset);
			if (((Blob_t)(master->children->items[index]))->magic == kSecCodeMagicEntitlement) {
				BufferRef child_data_ref = ((Blob_t)(master->children->items[index]))->data;
				NSData *plist = [NSData dataWithBytes:&(child_data_ref->data[8]) length:child_data_ref->length-8];
				NSLog(@"%@", [NSPropertyListSerialization propertyListWithData:plist options:0 format:nil error:nil]);
			}
			if (((Blob_t)(master->children->items[index]))->magic == kSecCodeMagicRequirement) {
				ParseRequirement(master->children->items[index]);
			}
		}
	}
	return master;
}

int main(int argc, const char * argv[]) {
	@autoreleasepool {
		if (argc == 2) {
			BufferRef signature_data = CreateBufferFromFilePath((char*)argv[1]);
			
			Blob_t master = FindBlobs(signature_data, 0);
			
		}
	}
    return 0;
}
