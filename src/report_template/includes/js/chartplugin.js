$.fn.chartInit = function(config) {
	return this.each(function() {
						 this._chart = new Chart(this,config);
					 });
};

$.fn.chartAdd = function(series) {
	return this.each(function() {
						 this._chart.add(series);
					 });
};

$.fn.chartClear = function() {
	return this.each(function() {
						 this._chart.clear();
					 });
};

$.fn.chartDraw = function(seriesLabel) {
	return this.each(function() {
						 this._chart.draw(seriesLabel);
					 });
};

