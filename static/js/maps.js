function initialize() {
	var mapOptions = {
		center: new google.maps.LatLng(42.4, -83.15),
		zoom: 11,
		mapTypeId: google.maps.MapTypeId.ROADMAP
	};
	var map = new google.maps.Map(document.getElementById("map_canvas"),
	mapOptions);
}