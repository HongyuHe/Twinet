package netstate

import "testing"

func TestParseRoutesPreservesBareHostRouteFromIPJSON(t *testing.T) {
	routes, err := parseRoutes([]byte(`[
		{"dst":"3.153.0.1","protocol":"ospf","table":"main",
		 "nexthops":[{"dev":"PHY"},{"dev":"BOS"}]},
		{"dst":"3.156.0.1","protocol":"ospf","table":"main",
		 "nexthops":[{"dev":"ATL"},{"dev":"NYC"},{"dev":"PHY"}]}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 || routes[0].Prefix != "3.153.0.1" ||
		len(routes[0].NextHops) != 2 || routes[1].Prefix != "3.156.0.1" ||
		len(routes[1].NextHops) != 3 {
		t.Fatalf("bare host-route JSON was not preserved: %#v", routes)
	}
}
