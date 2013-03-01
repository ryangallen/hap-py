(function(){
	if(!navigator.geolocation){
		alert('Your browser does not support geolocation.');
	}else{
		navigator.geolocation.getCurrentPosition(success, error);
	}
})();

	function success(position){
		var lat = position.coords.latitude,
			lon = position.coords.longitude;

		var options = {
			center: new google.maps.LatLng( lat, lon ),
			zoom: 12,
			mapTypeId: google.maps.MapTypeId.ROADMAP
		};

		var map = new google.maps.Map(document.getElementById('map_canvas'), options);
	}

	function error(error){
		alert("Sorry, an error occured:\n"+ error);
	}

