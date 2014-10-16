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
