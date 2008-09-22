/*----------------------------------------------------------------------------\
  |                                  Chart 1.0                                  |
  |                       JavaScript Graphics Chart Painter                     |
  |-----------------------------------------------------------------------------|
  |                          Created by Emil A Eklund                           |
  |                        (http://eae.net/contact/emil)                        |
  |                           Modified by Ma Bingyao                            |
  |                          (http://www.coolcode.cn)                           |
  |-----------------------------------------------------------------------------|
  | JavaScript Graphics implementation of the chart painter API.  jsGraphics is |
  | used to  draw the chart,  html elements are used for  the legend  and  axis |
  | labels as, at the time being.                                               |
  |-----------------------------------------------------------------------------|
  |                Copyright (c) 2006 Emil A Eklund & Ma Bingyao                |
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
  | 2006-02-03 | Modified to use wz_jsgraphics instead of canvas by Ma Bingyao. |
  | 2007-02-01 | Moved all Chart specific methods into the Chart class and      |
  |            | added simpler device specific drawing primitives.              |
  |            | (by Ashutosh Bijoor - bijoor@gmail.com)         .              |
  |-----------------------------------------------------------------------------|
  | Created 2006-01-03 | All changes are in the log above. | Updated 2007-02-01 |
  \----------------------------------------------------------------------------*/

function JsGraphicsChartPainterFactory() {
    return new JsGraphicsChartPainter();
}


function JsGraphicsChartPainter() {
    this.base = AbstractChartPainter;
};


JsGraphicsChartPainter.prototype = new AbstractChartPainter;


JsGraphicsChartPainter.prototype.create = function(el) {
    while (el.firstChild) { el.removeChild(el.lastChild); }

    this.el = el;
    this.w = el.clientWidth;
    this.h = el.clientHeight;

    this.canvas = document.createElement('div');
    this.canvas.width  = this.w;
    this.canvas.height = this.h;
    this.canvas.style.width  = this.w + 'px';
    this.canvas.style.height = this.h + 'px';
    this.canvas.style.position = "relative";
    this.canvas.id = "canvas_" + el.id;
    this.canvas.onselectstart = function () { return false; };

    el.appendChild(this.canvas);
    this.ctx = new jsGraphics(this.canvas.id);
};

JsGraphicsChartPainter.prototype.getWidth = function() {
    return this.w;
};

JsGraphicsChartPainter.prototype.getHeight = function() {
    return this.h;
};

JsGraphicsChartPainter.prototype.fillArea = function(color, points) {
    var i,XPoints,YPoints;
    XPoints=[];
    YPoints=[];
    if (points.length<=0) return;
    for(i=0;i<points.length;i++) {
	XPoints[i]=points[i].x;
	YPoints[i]=points[i].y;
    }
    this.ctx.setColor(color);
    this.ctx.fillPolygon(XPoints, YPoints);
};


JsGraphicsChartPainter.prototype.polyLine = function(color,lineWidth,points) {
    if (points.length<=0) return;
    this.ctx.setStroke(lineWidth);
    this.ctx.setColor(color);
    for (i = 1; i <points.length; i++) {
	this.ctx.drawLine(points[i-1].x, points[i-1].y,points[i].x, points[i].y);
    }
    this.ctx.paint();
};

JsGraphicsChartPainter.prototype.fillRect = function(color, x,y,width,height) {
    this.ctx.setColor(color);
    this.ctx.fillRect(x, y, width,height);
};

JsGraphicsChartPainter.prototype.line = function(color,lineWidth,x1,y1,x2,y2) {
    this.ctx.setStroke(lineWidth);
    this.ctx.setColor(color);
    this.ctx.drawLine(x1,y1,x2,y2);
    this.ctx.paint();
};

JsGraphicsChartPainter.prototype.fillArc = function(color,centerx,centery,radius,startAngle,endAngle) {
    this.ctx.setColor(color);
	this.ctx.fillArc(centerx, centery, radius, radius, startAngle, endAngle);
};

