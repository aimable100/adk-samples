# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.

"""The trusted alert record.

The ticket is granted from this object at hand-off. In a deployment it
arrives from the alerting system into session state. The model may talk
about the alert; it does not choose the service the ticket names.
"""

ALERT = {
    "id": "ALR-2291",
    "service": "web-checkout",
    "severity": "P2",
    "summary": "web-checkout p99 latency 4.8s over 5m (threshold 1.5s)",
}
