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
#import <mach-o/arch.h>

uint64_t counter = 0;

NSInteger ParseMagic(NSData *data, uint32_t offset) {
	uint8_t magic[4] = {0};
	[data getBytes:&magic range:NSMakeRange(offset, sizeof(uint32_t))];
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

NSInteger ParseLength(NSData *data) {
	uint32_t length = 0;
	[data getBytes:&length range:NSMakeRange(4, sizeof(uint32_t))];
	length = OSSwapHostToBigInt32(length);
	return length;
}

struct BlobLocation {
	uint32_t thing;
	uint32_t offset;
};

@interface Blob : NSObject
@property (nonatomic, readwrite) NSInteger magic;
@property (nonatomic, readwrite) struct BlobLocation position;
@property (nonatomic, strong) NSData *data;
@property (nonatomic, strong) NSArray *children;
@end

@implementation Blob

@end

int main(int argc, const char * argv[]) {
	@autoreleasepool {
		if (argc == 2) {
			NSData *signatureData = [NSData dataWithContentsOfFile:[NSString stringWithFormat:@"%s",argv[1]]];
			Blob *superBlob = [[Blob alloc] init];
			[superBlob setMagic:ParseMagic(signatureData, 0)];
			counter += sizeof(uint32_t);
			[superBlob setData:[NSData dataWithBytes:[signatureData bytes] length:ParseLength(signatureData)]];
			counter += sizeof(uint32_t);
			uint32_t children = 0;
			[signatureData getBytes:&children range:NSMakeRange(counter, sizeof(uint32_t))];
			counter += sizeof(uint32_t);
			children = OSSwapHostToBigInt32(children);
			NSMutableArray *childArray = [NSMutableArray new];
			for (uint32_t index = 0; index < children; index++) {
				struct BlobLocation *loc = calloc(1, sizeof(struct BlobLocation));
				[signatureData getBytes:loc range:NSMakeRange(counter, sizeof(struct BlobLocation))];
				loc->offset = OSSwapHostToBigInt32(loc->offset);
				counter += sizeof(struct BlobLocation);
				printf("found blob at: %d\n", loc->offset);
				Blob *child = [[Blob alloc] init];
				[child setMagic:ParseMagic(signatureData, loc->offset)];
				uint8_t *offset = (char*)[signatureData bytes] + loc->offset;
				NSData *childData = [NSData dataWithBytesNoCopy:offset length:[signatureData length] - loc->offset];
				[child setData:childData];
				[child setPosition:*loc];
				if ([child magic] == kSecCodeMagicEntitlement) {
					NSData *plist = [NSData dataWithBytes:[[child data] bytes]+8 length:ParseLength([child data])];
					NSLog(@"%@", [NSPropertyListSerialization propertyListWithData:plist options:0 format:nil error:nil]);
				}
				[childArray addObject:child];
			}
			[superBlob setChildren:childArray];
		}
	}
    return 0;
}
