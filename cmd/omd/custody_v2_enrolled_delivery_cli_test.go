package main

import "testing"

func TestAdmissionDeliveryEnrolledCLICompleteLifecycle(t *testing.T) {
	z := newEnrolledCLIFixtureWithLifetime(t, deliveryInProcess, 600)
	runAdmissionDeliveryCLIFixtureCampaign(t, z, deliveryInProcess, deliveryInProcessStart)
}
