/*----------------------------------------------------------------------------\
|                                  Chart 1.0                                  |
|                              SVG Chart Painter                              |
|-----------------------------------------------------------------------------|
|                          Created by Emil A Eklund                           |
|                        (http://eae.net/contact/emil)                        |
|-----------------------------------------------------------------------------|
| SVG implementation of the chart painter API.  A svg element is used to draw |
| draw the chart.  This implementation is not complete and is provided mostly |
| as a reference at this stage.                                               |
|-----------------------------------------------------------------------------|
|                      Copyright (c) 2006 Emil A Eklund                       |
|- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -|
| This program is  free software;  you can redistribute  it and/or  modify it |
| under the terms of the MIT License.                                         |
|- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -|
| Permission  is hereby granted,  free of charge, to  any person  obtaining a |
| copy of this software and associated documentation files (the "Software"),  |
| to deal in the  Software without restriction,  including without limitation |
| the  rights to use, copy, modify,  merge, publish, distribute,  sublicense, |
| and/or  sell copies  of the  Software, and to  permit persons to  whom  the |
| Software is  furnished  to do  so, subject  to  the  following  conditions: |
| The above copyright notice and this  permission notice shall be included in |
| all copies or substantial portions of the Software.                         |
|- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -|
| THE SOFTWARE IS PROVIDED "AS IS",  WITHOUT WARRANTY OF ANY KIND, EXPRESS OR |
| IMPLIED,  INCLUDING BUT NOT LIMITED TO  THE WARRANTIES  OF MERCHANTABILITY, |
| FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE |
| AUTHORS OR  COPYRIGHT  HOLDERS BE  LIABLE FOR  ANY CLAIM,  DAMAGES OR OTHER |
| LIABILITY, WHETHER  IN AN  ACTION OF CONTRACT, TORT OR  OTHERWISE,  ARISING |
| FROM,  OUT OF OR  IN  CONNECTION  WITH  THE  SOFTWARE OR THE  USE OR  OTHER |
| DEALINGS IN THE SOFTWARE.                                                   |
|- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -|
|                         http://eae.net/license/mit                          |
|-----------------------------------------------------------------------------|
| 2006-01-03 | Work started.                                                  |
| 2006-01-05 | Added legend and axis labels. Changed the painter api slightly |
|            | to allow two-stage initialization (required for ie/canvas) and |
|            | added legend/axis related methods. Also updated bar chart type |
|            | and added a few options, mostly related to bar charts.         |
| 2006-01-07 | Split painter implementations to separate files.               |
|-----------------------------------------------------------------------------|
| Created 2006-01-03 | All changes are in the log above. | Updated 2006-01-07 |
\----------------------------------------------------------------------------*/

function SVGChartPainterFactory() {
	return new SVGChartPainter();
}


function SVGChartPainter() {
	this.base = AbstractChartPainter;
};


SVGChartPainter.prototype = new AbstractChartPainter;


SVGChartPainter.prototype.create = function(el) {
	this.svg = el;
	this.w = this.svg.getAttribute('width');
	this.h = this.svg.getAttribute('height');
};


SVGChartPainter.prototype.init = function(xlen, ymin, ymax, xgd, ygd, bLegendLabels) {
	this.calc(this.w, this.h, xlen, ymin, ymax, xgd, ygd);
};


SVGChartPainter.prototype.drawBackground = function() {
	while (this.svg.firstChild) { this.svg.removeChild(this.svg.lastChild); }
	this._drawRect('white', 0, 0, this.w, this.h);
};


SVGChartPainter.prototype.drawChart = function() {
	if (this.xgrid) {
		for (i = this.xgrid; i < this.w; i += this.xgrid) {
			this._drawRect('silver', 0 + i, 0, 1, this.h-1);
	}	}
	if (this.ygrid) {
		for (i = this.h - this.ygrid; i > 0; i -= this.ygrid) {
			this._drawRect('silver', 1, 0 + i, this.w, 1);
}	}	};


SVGChartPainter.prototype.drawAxis = function() {
	this._drawRect('black', 0, 0, 1, this.h);
	this._drawRect('black', 0, this.h-1, this.w, 1);
};


SVGChartPainter.prototype.drawArea = function(color, values) {
	var i, len, x, y, n, yoffset, path, o;

	/* Determine distance between points and offset */
	n = this.range/this.h;
	yoffset = (this.ymin / n);

	len = values.length;
	if (len) {

		/* Begin line in lower left corner */
		x = 1;
		path = 'M' + x + ',' + (this.h-1);

		/* Determine position of first point and append line to command */
		y = this.h - (values[0] / n) + yoffset;
		path += ' L' + x + ',' + y;

		/* Append commands for succeeding points */
		for (i = 1; i < len; i++) {
			y = this.h - (values[i] / n) + yoffset;
			x += this.xstep;
			path += ' L' + x + ',' + y;
		}

		/* Close path and fill it */
		path += ' L' + x + ',' + (this.h-1) + ' Z';
		o = document.createElementNS('http://www.w3.org/2000/svg', 'path');
		o.setAttribute('stroke', color);
		o.setAttribute('fill', color);
		o.setAttribute('d', path);
		this.svg.appendChild(o);
}	};


SVGChartPainter.prototype.drawLine = function(color, values) {
	var i, len, x, y, n, yoffset, path, o;

	/* Determine distance between points and offset */
	n = this.range/this.h;
	yoffset = (this.ymin / n);

	len = values.length;
	if (len) {

		/* Determine position of first point and start path */
		x = 1;
		y = this.h - (values[0] / n) + yoffset;
		path = 'M' + x + ',' + y;

		/* Append line to commands for succeeding points */
		for (i = 1; i < len; i++) {
			y = this.h - (values[i] / n) + yoffset;
			x += this.xstep;
			path += ' L' + x + ',' + y;
		}

		/* Draw path */
		o = document.createElementNS('http://www.w3.org/2000/svg', 'path');
		o.setAttribute('stroke', color);
		o.setAttribute('fill', 'none');
		o.setAttribute('stroke-width', '1px');
		o.setAttribute('d', path);
		this.svg.appendChild(o);
}	};


SVGChartPainter.prototype.drawBars = function(color, values, xoffset, width) {
	var i, len, x, y, n, yoffset;

	/* Determine distance between points and offset */
	n = this.range/this.h;
	yoffset = (this.ymin / n);

	len = values.length;
	if (len) {

		/* Determine position of each bar and draw it */
		x = xoffset + 1;
		for (i = 0; i < len; i++) {
			y = this.h - (values[i] / n);
			this._drawRect(color, x, y, width, this.h - y);
			x += this.xstep;
}	}	};


SVGChartPainter.prototype._drawRect = function(color, x, y, w, h) {
	var rect;

	rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
	rect.setAttribute('stroke', 'none');
	rect.setAttribute('fill', color);
	rect.setAttribute('x', x + 'px');
	rect.setAttribute('y', y + 'px');
	rect.setAttribute('width', w + 'px');
	rect.setAttribute('height', h + 'px');

	this.svg.appendChild(rect);
};
