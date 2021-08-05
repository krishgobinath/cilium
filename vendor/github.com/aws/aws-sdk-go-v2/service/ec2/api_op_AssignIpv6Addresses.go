// Code generated by smithy-go-codegen DO NOT EDIT.

package ec2

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Assigns one or more IPv6 addresses to the specified network interface. You can
// specify one or more specific IPv6 addresses, or you can specify the number of
// IPv6 addresses to be automatically assigned from within the subnet's IPv6 CIDR
// block range. You can assign as many IPv6 addresses to a network interface as you
// can assign private IPv4 addresses, and the limit varies per instance type. For
// information, see IP Addresses Per Network Interface Per Instance Type
// (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html#AvailableIpPerENI)
// in the Amazon Elastic Compute Cloud User Guide. You must specify either the IPv6
// addresses or the IPv6 address count in the request. You can optionally use
// Prefix Delegation on the network interface. You must specify either the IPV6
// Prefix Delegation prefixes, or the IPv6 Prefix Delegation count. For
// information, see Prefix Delegation
// (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-prefix-delegation) in
// the Amazon Elastic Compute Cloud User Guide.
func (c *Client) AssignIpv6Addresses(ctx context.Context, params *AssignIpv6AddressesInput, optFns ...func(*Options)) (*AssignIpv6AddressesOutput, error) {
	if params == nil {
		params = &AssignIpv6AddressesInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "AssignIpv6Addresses", params, optFns, c.addOperationAssignIpv6AddressesMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*AssignIpv6AddressesOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type AssignIpv6AddressesInput struct {

	// The ID of the network interface.
	//
	// This member is required.
	NetworkInterfaceId *string

	// The number of additional IPv6 addresses to assign to the network interface. The
	// specified number of IPv6 addresses are assigned in addition to the existing IPv6
	// addresses that are already assigned to the network interface. Amazon EC2
	// automatically selects the IPv6 addresses from the subnet range. You can't use
	// this option if specifying specific IPv6 addresses.
	Ipv6AddressCount *int32

	// One or more specific IPv6 addresses to be assigned to the network interface. You
	// can't use this option if you're specifying a number of IPv6 addresses.
	Ipv6Addresses []string

	// The number of IPv6 Prefix Delegation prefixes that AWS automatically assigns to
	// the network interface. You cannot use this option if you use the Ipv6Prefixes
	// option.
	Ipv6PrefixCount *int32

	// One or more IPv6 Prefix Delegation prefixes assigned to the network interface.
	// You cannot use this option if you use the Ipv6PrefixCount option.
	Ipv6Prefixes []string

	noSmithyDocumentSerde
}

type AssignIpv6AddressesOutput struct {

	// The new IPv6 addresses assigned to the network interface. Existing IPv6
	// addresses that were assigned to the network interface before the request are not
	// included.
	AssignedIpv6Addresses []string

	// The IPv6 Prefix Delegation prefixes that are assigned to the network interface.
	AssignedIpv6Prefixes []string

	// The ID of the network interface.
	NetworkInterfaceId *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationAssignIpv6AddressesMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpAssignIpv6Addresses{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpAssignIpv6Addresses{}, middleware.After)
	if err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddClientRequestIDMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddComputeContentLengthMiddleware(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = v4.AddComputePayloadSHA256Middleware(stack); err != nil {
		return err
	}
	if err = addRetryMiddlewares(stack, options); err != nil {
		return err
	}
	if err = addHTTPSignerV4Middleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = awsmiddleware.AddRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addClientUserAgent(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addOpAssignIpv6AddressesValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opAssignIpv6Addresses(options.Region), middleware.Before); err != nil {
		return err
	}
	if err = addRequestIDRetrieverMiddleware(stack); err != nil {
		return err
	}
	if err = addResponseErrorMiddleware(stack); err != nil {
		return err
	}
	if err = addRequestResponseLogging(stack, options); err != nil {
		return err
	}
	return nil
}

func newServiceMetadataMiddleware_opAssignIpv6Addresses(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "AssignIpv6Addresses",
	}
}
