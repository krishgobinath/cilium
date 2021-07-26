// +build !ignore_autogenerated

// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2021 Authors of Cilium

// Code generated by deepcopy-gen. DO NOT EDIT.

package v2alpha1

import (
	models "github.com/cilium/cilium/api/v1/models"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumEgressNATPolicy) DeepCopyInto(out *CiliumEgressNATPolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumEgressNATPolicy.
func (in *CiliumEgressNATPolicy) DeepCopy() *CiliumEgressNATPolicy {
	if in == nil {
		return nil
	}
	out := new(CiliumEgressNATPolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CiliumEgressNATPolicy) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumEgressNATPolicyList) DeepCopyInto(out *CiliumEgressNATPolicyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]CiliumEgressNATPolicy, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumEgressNATPolicyList.
func (in *CiliumEgressNATPolicyList) DeepCopy() *CiliumEgressNATPolicyList {
	if in == nil {
		return nil
	}
	out := new(CiliumEgressNATPolicyList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CiliumEgressNATPolicyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumEgressNATPolicySpec) DeepCopyInto(out *CiliumEgressNATPolicySpec) {
	*out = *in
	if in.Egress != nil {
		in, out := &in.Egress, &out.Egress
		*out = make([]EgressRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.DestinationCIDRs != nil {
		in, out := &in.DestinationCIDRs, &out.DestinationCIDRs
		*out = make([]IPv4CIDR, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumEgressNATPolicySpec.
func (in *CiliumEgressNATPolicySpec) DeepCopy() *CiliumEgressNATPolicySpec {
	if in == nil {
		return nil
	}
	out := new(CiliumEgressNATPolicySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumEndpointSlice) DeepCopyInto(out *CiliumEndpointSlice) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	if in.Endpoints != nil {
		in, out := &in.Endpoints, &out.Endpoints
		*out = make([]CoreCiliumEndpoint, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumEndpointSlice.
func (in *CiliumEndpointSlice) DeepCopy() *CiliumEndpointSlice {
	if in == nil {
		return nil
	}
	out := new(CiliumEndpointSlice)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CiliumEndpointSlice) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumEndpointSliceList) DeepCopyInto(out *CiliumEndpointSliceList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]CiliumEndpointSlice, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumEndpointSliceList.
func (in *CiliumEndpointSliceList) DeepCopy() *CiliumEndpointSliceList {
	if in == nil {
		return nil
	}
	out := new(CiliumEndpointSliceList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CiliumEndpointSliceList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CoreCiliumEndpoint) DeepCopyInto(out *CoreCiliumEndpoint) {
	*out = *in
	if in.Networking != nil {
		in, out := &in.Networking, &out.Networking
		*out = new(v2.EndpointNetworking)
		(*in).DeepCopyInto(*out)
	}
	out.Encryption = in.Encryption
	if in.NamedPorts != nil {
		in, out := &in.NamedPorts, &out.NamedPorts
		*out = make(models.NamedPorts, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(models.Port)
				**out = **in
			}
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CoreCiliumEndpoint.
func (in *CoreCiliumEndpoint) DeepCopy() *CoreCiliumEndpoint {
	if in == nil {
		return nil
	}
	out := new(CoreCiliumEndpoint)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EgressRule) DeepCopyInto(out *EgressRule) {
	*out = *in
	if in.NamespaceSelector != nil {
		in, out := &in.NamespaceSelector, &out.NamespaceSelector
		*out = new(v1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.PodSelector != nil {
		in, out := &in.PodSelector, &out.PodSelector
		*out = new(v1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EgressRule.
func (in *EgressRule) DeepCopy() *EgressRule {
	if in == nil {
		return nil
	}
	out := new(EgressRule)
	in.DeepCopyInto(out)
	return out
}
