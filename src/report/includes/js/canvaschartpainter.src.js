/*----------------------------------------------------------------------------\
  |                                  Chart 1.0                                  |
  |                            Canvas Chart Painter                             |
  |-----------------------------------------------------------------------------|
  |                          Created by Emil A Eklund                           |
  |                        (http://eae.net/contact/emil)                        |
  |-----------------------------------------------------------------------------|
  | Canvas implementation of the chart painter API. A canvas element is used to |
  | draw the chart,  html elements are used for the legend and  axis labels as, |
  | at the time being, there is no text support in canvas.                      |
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
  | 2006-01-07 | Updated chart size calculations to take legend and axis labels |
  |            | into consideration.  Split painter implementations to separate |
  |            | files.                                                         |
  | 2006-04-16 | Updated to use the  ExplorerCanvas ie emulation  layer instead |
  |            | of the, now deprecated, IECanvas one.                          |
  | 2007-02-01 | Moved all Chart specific methods into the Chart class and      |
  |            | added simpler device specific drawing primitives.              |
  |            | (by Ashutosh Bijoor - bijoor@gmail.com)         .              |
  |-----------------------------------------------------------------------------|
  | Created 2006-01-03 | All changes are in the log above. | Updated 2007-02-01 |
  \----------------------------------------------------------------------------*/

function CanvasChartPainterFactory() {
    return new CanvasChartPainter();
}


function CanvasChartPainter() {
    this.base = AbstractChartPainter;
};


CanvasChartPainter.prototype = new AbstractChartPainter;


CanvasChartPainter.prototype.create = function(el) {
    while (el.firstChild) { el.removeChild(el.lastChild); }

    this.el = el;
    this.w = el.clientWidth;
    this.h = el.clientHeight;

    this.canvas = document.createElement('canvas');
    this.canvas.width  = this.w;
    this.canvas.height = this.h;
    this.canvas.style.width  = this.w + 'px';
    this.canvas.style.height = this.h + 'px';

    el.appendChild(this.canvas);
	
    /* Init explorercanvas emulation for IE */
    if ((!this.canvas.getContext) && (typeof G_vmlCanvasManager != "undefined")) {
	this.canvas = G_vmlCanvasManager.initElement(this.canvas);
    }
    this.ctx = this.canvas.getContext('2d');
};

CanvasChartPainter.prototype.getWidth = function() {
    return this.w;
};

CanvasChartPainter.prototype.getHeight = function() {
    return this.h;
};

CanvasChartPainter.prototype.fillArea = function(color, points) {
    if (points.length<=0) return;
    this.ctx.fillStyle = color;

    /* Begin path */
    this.ctx.beginPath();
    this.ctx.moveTo(points[0].x,points[0].y);

    /* Draw lines to succeeding points */
    for (i = 1; i < points.length; i++) {
	this.ctx.lineTo(points[i].x, points[i].y);
    }

    /* Close path and fill it */
    this.ctx.lineTo(points[0].x, points[0].y);
    this.ctx.closePath();
    this.ctx.fill();
};


CanvasChartPainter.prototype.polyLine = function(color,lineWidth,points) {
    if (points.length<=0) return;
    this.ctx.lineWidth   = lineWidth;
    this.ctx.strokeStyle = color;
    this.ctx.beginPath();
    this.ctx.moveTo(points[0].x,points[0].y);
    for(var i=1;i<points.length;i++) {
	this.ctx.lineTo(points[i].x,points[i].y);
    }
    /* Stroke path */
    this.ctx.stroke();
};

CanvasChartPainter.prototype.fillRect = function(color, x,y,width,height) {
    //try {
		this.ctx.fillStyle = color;
		this.ctx.fillRect(x, y,width,height);
		//} catch(e) {
		//alert("Error: Invalid dimensions for fillRect:"+x+","+y+","+width+","+height);
		// }
};

CanvasChartPainter.prototype.line = function(color,lineWidth,x1,y1,x2,y2) {
    this.ctx.lineWidth   = parseInt(lineWidth);
    this.ctx.strokeStyle = color;
    this.ctx.beginPath();
    this.ctx.moveTo(x1,y1);
    this.ctx.lineTo(x2,y2);
    this.ctx.stroke();
};

CanvasChartPainter.prototype.fillArc = function(color,centerx,centery,radius,startAngle,endAngle) {
	this.ctx.fillStyle = color;
	this.ctx.beginPath();
	this.ctx.moveTo(centerx, centery);
	// convert angles into radians
	startAngle=startAngle*Math.PI/180;
	endAngle=endAngle*Math.PI/180;
	this.ctx.arc(centerx, centery, radius, 
				 startAngle,
				 endAngle,
				 false);
	this.ctx.lineTo(centerx, centery);
	this.ctx.closePath();
	this.ctx.fill();
};
