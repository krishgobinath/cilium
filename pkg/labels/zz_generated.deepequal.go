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

package labels

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *Label) DeepEqual(other *Label) bool {
	if other == nil {
		return false
	}

	if in.Key != other.Key {
		return false
	}
	if in.Value != other.Value {
		return false
	}
	if in.Source != other.Source {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *LabelArray) DeepEqual(other *LabelArray) bool {
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

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *LabelArrayList) DeepEqual(other *LabelArrayList) bool {
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

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *Labels) DeepEqual(other *Labels) bool {
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
				if !inValue.DeepEqual(&otherValue) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *OpLabels) DeepEqual(other *OpLabels) bool {
	if other == nil {
		return false
	}

	if ((in.Custom != nil) && (other.Custom != nil)) || ((in.Custom == nil) != (other.Custom == nil)) {
		in, other := &in.Custom, &other.Custom
		if other == nil || !in.DeepEqual(other) {
			return false
		}
	}

	if ((in.OrchestrationIdentity != nil) && (other.OrchestrationIdentity != nil)) || ((in.OrchestrationIdentity == nil) != (other.OrchestrationIdentity == nil)) {
		in, other := &in.OrchestrationIdentity, &other.OrchestrationIdentity
		if other == nil || !in.DeepEqual(other) {
			return false
		}
	}

	if ((in.Disabled != nil) && (other.Disabled != nil)) || ((in.Disabled == nil) != (other.Disabled == nil)) {
		in, other := &in.Disabled, &other.Disabled
		if other == nil || !in.DeepEqual(other) {
			return false
		}
	}

	if ((in.OrchestrationInfo != nil) && (other.OrchestrationInfo != nil)) || ((in.OrchestrationInfo == nil) != (other.OrchestrationInfo == nil)) {
		in, other := &in.OrchestrationInfo, &other.OrchestrationInfo
		if other == nil || !in.DeepEqual(other) {
			return false
		}
	}

	return true
}
