//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// Copyright 2017-2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by main. DO NOT EDIT.

package v1

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *LabelSelector) DeepEqual(other *LabelSelector) bool {
	if other == nil {
		return false
	}

	if ((in.MatchLabels != nil) && (other.MatchLabels != nil)) || ((in.MatchLabels == nil) != (other.MatchLabels == nil)) {
		in, other := &in.MatchLabels, &other.MatchLabels
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for key, inValue := range *in {
				if otherValue, present := (*other)[key]; !present {
					return false
				} else {
					if inValue != otherValue {
						return false
					}
				}
			}
		}
	}

	if ((in.MatchExpressions != nil) && (other.MatchExpressions != nil)) || ((in.MatchExpressions == nil) != (other.MatchExpressions == nil)) {
		in, other := &in.MatchExpressions, &other.MatchExpressions
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *LabelSelectorRequirement) DeepEqual(other *LabelSelectorRequirement) bool {
	if other == nil {
		return false
	}

	if in.Key != other.Key {
		return false
	}
	if in.Operator != other.Operator {
		return false
	}
	if ((in.Values != nil) && (other.Values != nil)) || ((in.Values == nil) != (other.Values == nil)) {
		in, other := &in.Values, &other.Values
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if inElement != (*other)[i] {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *ListMeta) DeepEqual(other *ListMeta) bool {
	if other == nil {
		return false
	}

	if in.ResourceVersion != other.ResourceVersion {
		return false
	}
	if in.Continue != other.Continue {
		return false
	}
	if (in.RemainingItemCount == nil) != (other.RemainingItemCount == nil) {
		return false
	} else if in.RemainingItemCount != nil {
		if *in.RemainingItemCount != *other.RemainingItemCount {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *ObjectMeta) DeepEqual(other *ObjectMeta) bool {
	if other == nil {
		return false
	}

	if in.Name != other.Name {
		return false
	}
	if in.Namespace != other.Namespace {
		return false
	}
	if in.UID != other.UID {
		return false
	}
	if ((in.Labels != nil) && (other.Labels != nil)) || ((in.Labels == nil) != (other.Labels == nil)) {
		in, other := &in.Labels, &other.Labels
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for key, inValue := range *in {
				if otherValue, present := (*other)[key]; !present {
					return false
				} else {
					if inValue != otherValue {
						return false
					}
				}
			}
		}
	}

	if ((in.Annotations != nil) && (other.Annotations != nil)) || ((in.Annotations == nil) != (other.Annotations == nil)) {
		in, other := &in.Annotations, &other.Annotations
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for key, inValue := range *in {
				if otherValue, present := (*other)[key]; !present {
					return false
				} else {
					if inValue != otherValue {
						return false
					}
				}
			}
		}
	}

	if ((in.OwnerReferences != nil) && (other.OwnerReferences != nil)) || ((in.OwnerReferences == nil) != (other.OwnerReferences == nil)) {
		in, other := &in.OwnerReferences, &other.OwnerReferences
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *OwnerReference) DeepEqual(other *OwnerReference) bool {
	if other == nil {
		return false
	}

	if in.Kind != other.Kind {
		return false
	}
	if in.Name != other.Name {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *PartialObjectMetadata) DeepEqual(other *PartialObjectMetadata) bool {
	if other == nil {
		return false
	}

	if in.TypeMeta != other.TypeMeta {
		return false
	}

	if !in.ObjectMeta.DeepEqual(&other.ObjectMeta) {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *PartialObjectMetadataList) DeepEqual(other *PartialObjectMetadataList) bool {
	if other == nil {
		return false
	}

	if in.TypeMeta != other.TypeMeta {
		return false
	}

	if !in.ListMeta.DeepEqual(&other.ListMeta) {
		return false
	}

	if ((in.Items != nil) && (other.Items != nil)) || ((in.Items == nil) != (other.Items == nil)) {
		in, other := &in.Items, &other.Items
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *Timestamp) DeepEqual(other *Timestamp) bool {
	if other == nil {
		return false
	}

	if in.Seconds != other.Seconds {
		return false
	}
	if in.Nanos != other.Nanos {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *TypeMeta) DeepEqual(other *TypeMeta) bool {
	if other == nil {
		return false
	}

	if in.Kind != other.Kind {
		return false
	}
	if in.APIVersion != other.APIVersion {
		return false
	}

	return true
}
