/*----------------------------------------------------------------------------\
  |                                  Chart 1.0                                  |
  |-----------------------------------------------------------------------------|
  |                          Created by Emil A Eklund                           |
  |                        (http://eae.net/contact/emil)                        |
  |-----------------------------------------------------------------------------|
  | Client side chart painter, supports line, area and bar charts and stacking, |
  | uses Canvas (mozilla,  safari,  opera) or SVG (mozilla, opera) for drawing. |
  | Can be used with IECanvas to allow the canvas painter to be used in IE.     |
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
  | Dependencies: canvaschartpainter.js  - Canvas chart painter implementation. |
  |               canvaschart.css        - Canvas chart painter styles.         |
  |           or: svgchartpainter.js     - SVG chart painter implementation.    |
  |-----------------------------------------------------------------------------|
  | 2006-01-03 | Work started.                                                  |
  | 2006-01-05 | Added legend and axis labels. Changed the painter api slightly |
  |            | to allow two-stage initialization (required for ie/canvas) and |
  |            | added legend/axis related methods. Also updated bar chart type |
  |            | and added a few options, mostly related to bar charts.         |
  | 2006-01-07 | Updated chart size calculations to take legend and axis labels |
  |            | into consideration.  Split painter implementations to separate |
  |            | files.                                                         |
  | 2006-01-10 | Fixed bug in automatic range calculation.  Also added explicit |
  |            | cast to float for stacked series.                              |
  | 2006-04-16 | Updated constructor to set painter factory  based on available |
  |            | and supported implementations.                                 |
  | 2007-02-01 | Brought chart related methods of PainterFactory classes into   |
  |            | the Chart class, and reduced PainterFactory to simpler drawing |
  |            | primitives only. (by Ashutosh Bijoor  -bijoor@gmail.com)       |
  |-----------------------------------------------------------------------------|
  | Created 2006-01-03 | All changes are in the log above. | Updated 2007-02-01 |
  \----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------\
  |                                    Chart                                    |
  |- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -|
  | Chart class, control class that's used to represent a chart. Uses a painter |
  | class for the actual drawing.  This is the only  class that should be  used |
  | directly, the other ones are internal.                                      |
  \----------------------------------------------------------------------------*/

function Chart(el) {
	this._cont             = el;
	this._yMin             = null;
	this._yMax             = null;
	this._xGridDensity     = 0;
	this._yGridDensity     = 0;
	this._flags            = 0;
	this._series           = new Array();
	this._labelPrecision   = 0;
	this._horizontalLabels = new Array();
	this._barWidth         = 10;
	this._barDistance      = 2;
	this._bars             = 0;
	this._showLegend       = true;
	this._painter          = null;
	
	/*
	 * Determine painter implementation to use based on what's available and
	 * supported. CanvasChartPainter is the prefered one, JsGraphicsChartPainter
	 * the fallback one as it works in pretty much any browser. The
	 * SVGChartPainter implementation one will only be used if set explicitly as
	 * it's not up to pair with the other ones.
	 */
	if ((typeof CanvasChartPainterFactory != 'undefined') && (window.CanvasRenderingContext2D)) {
		this.setPainterFactory(CanvasChartPainterFactory);
	}
	else if (typeof JsGraphicsChartPainterFactory != 'undefined') {
		this.setPainterFactory(JsGraphicsChartPainterFactory);
	}
	else { this._painterFactory = null; }

}


Chart.prototype.setPainterFactory = function(f) {
	this._painterFactory = f;
	/* Create painter object */
	this._painter = this._painterFactory();
	this._painter.create(this._cont);
};

Chart.prototype.getPainter = function() {
	return this._painter;
};


Chart.prototype.setVerticalRange = function(min, max) {
	this._yMin = min;
	this._yMax = max;
};


Chart.prototype.setLabelPrecision = function(precision) {
	this._labelPrecision = precision;
};


Chart.prototype.setShowLegend = function(b) {
	this._showLegend = b;
};


Chart.prototype.setGridDensity = function(horizontal, vertical) {
	this._xGridDensity = horizontal;
	this._yGridDensity = vertical;
};


Chart.prototype.setHorizontalLabels = function(labels) {
	this._horizontalLabels = labels;
};


Chart.prototype.add = function(series) {
	this._series.push(series);
};


Chart.prototype.draw = function() {
	var i, o, o2, len, xlen, ymin, ymax, type, self, bLabels;
	
	if (!this._painter) { return; }

	/* Initialize */
	this.xlen = 0;
	this.ymin = this._yMin;
	this.ymax = this._yMax;

	/* Determine maximum number of values, ymin and ymax */
	for (i = 0; i < this._series.length; i++) {
		this._series[i].setRange(this);
	}

	/*
	 * For bar only charts the number of charts is the same as the length of the
	 * longest series, for others combinations it's one less. Compensate for that
	 * for bar only charts.
	 */
	
	//if (this._series.length == this._bars) {
	this.xlen++;
	this._xGridDensity++;
	//}

	/*
	 * Determine whatever or not to show the legend and axis labels
	 * Requires density and labels to be set.
	 */

	//bLabels = ((this._xGridDensity) && (this._yGridDensity) && (this._horizontalLabels.length >= this._xGridDensity));
	bLabels = (this._xGridDensity) && (this._yGridDensity);

	/* Initialize painter object */
	this.init(this.xlen, this.ymin, this.ymax, this._xGridDensity, this._yGridDensity, bLabels);
	
	/* Draw chart background */
	this.drawBackground();
	
	/*
	 * If labels and grid density where specified, draw legend and labels.
	 * It's drawn prior to the chart as the size of the legend and labels
	 * affects the size of the chart area.
	 */
	if (this._showLegend) { this.drawLegend(); }

	if (bLabels) {
	    this.drawVerticalAxis(this._yGridDensity, this._labelPrecision);
	    this.drawHorizontalAxis(this.xlen, this._horizontalLabels, this._xGridDensity, this._labelPrecision);
	}
	    
	/* Draw grid */
	this.drawGrid();

	/* Draw series */
	for (i = 0; i < this._series.length; i++) {
		this._series[i].draw(this);
	}

	/*
	 * Draw axis (after the series since the anti aliasing of the lines may
	 * otherwise be drawn on top of the axis)
	 */
	this.drawAxis();

};


Chart.prototype.init = function(xlen, ymin, ymax, xgd, ygd, bLegendLabels) {

    this.w=this._painter.getWidth();
    this.h=this._painter.getHeight();
    this.chartx = 0;
    this.chartw	= this.w;
    this.charth	= this.h;
    this.charty = 0;
	
    this.xlen = xlen;
    this.ymin = ymin;
    this.ymax = ymax;
    this.xgd  = xgd;
    this.ygd  = ygd;

    this.calc(this.chartw, this.charth, xlen, ymin, ymax, xgd, ygd);
};

Chart.prototype.calc = function(w, h, xlen, ymin, ymax, xgd, ygd) {
    this.range = ymax - ymin;
    this.xstep = w / (xlen - 1);
    this.xgrid = (xgd)?w / (xgd - 1):0;
    this.ygrid = (ygd)?h / (ygd - 1):0;
    this.ymin  = ymin;
    this.ymax  = ymax;
};

Chart.prototype.findSeries = function(label) {
    for (var i = 0; i < this._series.length; i++) {
		if (this._series[i].getLabel()==label) {
			return this._series[i];
		}
	}
	return null;
};

Chart.prototype.drawLegend = function() {
    var legend, list, item, label;
	var series=this._series;
    legend = document.createElement('div');
    legend.className = 'legend';
    legend.style.position = 'absolute';
    list = document.createElement('ul');

    for (i = 0; i < series.length; i++) {
		item = document.createElement('li');
		item.style.color = series[i].getColor();
		label = document.createElement('span');
		label.appendChild(document.createTextNode(series[i].getLabel()));
		label.style.color = 'black';
		item.appendChild(label);
		list.appendChild(item);
    }
    legend.appendChild(list);
    this._cont.appendChild(legend);
    legend.style.right = '0px';
    legend.style.top  = this.charty + (this.charth / 2) - (legend.offsetHeight / 2) + 'px';
    this.legend = legend;
	
    /* Recalculate chart width and position based on labels and legend */
    this.chartw	= this.w - (this.legend.offsetWidth + 5);
	
    this.calc(this.chartw, this.charth, this.xlen, this.ymin, this.ymax, this.xgd, this.ygd);
};


Chart.prototype.drawVerticalAxis = function(ygd, precision) {
    var axis, item, step, y, ty, n, yoffset, value, multiplier, w, items, pos;

    /* Calculate step size and rounding precision */
    multiplier = Math.pow(10, precision);
    step       = this.range / (ygd - 1);

    /* Create container */
    axis = document.createElement('div');
    axis.style.position = 'absolute';
    axis.style.left  = '0px';
    axis.style.top   = '0px';
    axis.style.textAlign = 'right';
    this._cont.appendChild(axis);
	
    /* Draw labels and points */
    w = 0;
    items = new Array();
    for (n = 0, i = this.ymax; (i > this.ymin) && (n < ygd - 1); i -= step, n++) {
		item = document.createElement('span');
		value = parseInt(i * multiplier) / multiplier;
		item.appendChild(document.createTextNode(value));
		axis.appendChild(item);
		items.push([i, item]);
		if (item.offsetWidth > w) { w = item.offsetWidth; }
    }
	
    /* Draw last label and point (lower left corner of chart) */
    item = document.createElement('span');
    item.appendChild(document.createTextNode(this.ymin));
    axis.appendChild(item);
    items.push([this.ymin, item]);
    if (item.offsetWidth > w) { w = item.offsetWidth; }
	
    /* Set width of container to width of widest label */
    axis.style.width = w + 'px';
	
    /* Recalculate chart width and position based on labels and legend */
    this.chartx = w + 5;
    this.charty = item.offsetHeight / 2;
    this.charth = this.h - ((item.offsetHeight * 1.5) + 5);
    this.chartw	= this.w - (((this.legend)?this.legend.offsetWidth:0) + w + 10);
    this.calc(this.chartw, this.charth, this.xlen, this.ymin, this.ymax, this.xgd, this.ygd);
	
    /* Position labels on the axis */
    n          = this.range / this.charth;
    yoffset    = (this.ymin / n);
    for (i = 0; i < items.length; i++) {
		item = items[i][1];
		pos = items[i][0];
		if (pos == this.ymin) { y = this.charty + this.charth - 1; }
		else { y = this.charty + (this.charth - (pos / n) + yoffset); }
		this._painter.fillRect('black',this.chartx - 5, y, 5, 1);
		ty = y - (item.offsetHeight/2);
		item.style.position = 'absolute';
		item.style.right = '0px';
		item.style.top   = ty + 'px';
    }	
};


Chart.prototype.drawHorizontalAxis = function(xlen, labels, xgd, precision) {
    var axis, item, step, x, tx, n, multiplier;

    /* Calculate offset, step size and rounding precision */
    multiplier = Math.pow(10, precision);
    n          = this.chartw / (xgd - 1);

    /* Create container */
    axis = document.createElement('div');
    axis.style.position = 'absolute';
    axis.style.left   = '0px';
    axis.style.top    = (this.charty + this.charth + 5) + 'px';
    axis.style.width  = this.w + 'px';
    this._cont.appendChild(axis);

    /* Draw labels and points */
    for (i = 0; i < xgd; i++) {
		item = document.createElement('span');
		if (labels[i]) {
			item.appendChild(document.createTextNode(labels[i]));
		}
		axis.appendChild(item);
		x = this.chartx + (n * i);
		tx = x - (item.offsetWidth/2);
		item.style.position = 'absolute';
		item.style.left = tx + 'px';
		item.style.top  = '0px';
		this._painter.fillRect('black',x, this.charty + this.charth, 1, 5);
    }	
};


Chart.prototype.drawAxis = function() {
    var x1, x2, y1, y2;
    x1 = this.chartx;
    x2 = this.chartx + this.chartw + 1;
    y1 = this.charty;
    y2 = this.charty + this.charth - 1;
    this._painter.line('black',1,x1, y1, x1, y2);
    this._painter.line('black',1,x1, y2, x2, y2);
};


Chart.prototype.drawBackground = function() {
    this._painter.fillRect('white',0, 0, this.w, this.h);
};


Chart.prototype.drawGrid = function() {
    if (this.xgrid) {
		for (i = this.xgrid; i < this.chartw; i += this.xgrid) {
			this._painter.line('silver',1,this.chartx + i, this.charty, this.chartx + i, this.charty + this.charth - 1);
		}
    }
    if (this.ygrid) {
		for (i = this.charth - this.ygrid; i > 0; i -= this.ygrid) {
			this._painter.line('silver',1,this.chartx + 1, this.charty + i, this.chartx + this.chartw + 1, this.charty + i);
		}
    }
};


/*----------------------------------------------------------------------------\
  |                         AbstractChartSeries                                 |
  |- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -|
  | Abstract class for common methods across all types of Charts                |
  \----------------------------------------------------------------------------*/

function AbstractChartSeries() {
}

AbstractChartSeries.prototype.getColor = function() {
	return this.data['color'];
};
	
AbstractChartSeries.prototype.getLabel = function() {
	return this.data['label'];
};


AbstractChartSeries.prototype.setRange = function(chart) {
	if (this.data['values'].length > chart.xlen) { chart.xlen = this.data['values'].length; }
	for (var j = 0; j < this.data['values'].length; j++) {
		if ((this.data['values'][j] < chart.ymin) || (chart.ymin == null))  { chart.ymin = this.data['values'][j]; }
		if (this.data['values'][j] > chart.ymax) { chart.ymax = this.data['values'][j]; }
	}
};

AbstractChartSeries.prototype.getStackedValues = function(chart) {
	var stacked=new Array();
	if (this.data['stackedOn']) {
		var stackedSeries=chart.findSeries(this.data['stackedOn']);
		if (stackedSeries) {
			stacked=stackedSeries.getStackedValues(chart);
		}
	}
	for(var i=0;i<this.data['values'].length;i++) {
		if (stacked[i]) {
			stacked[i]+=this.data['values'][i];
		} else {
			stacked[i]=this.data['values'][i];
		}
	}
	return stacked;
};

AbstractChartSeries.prototype.setConfig = function(name,value) {
	if (!value && typeof name == Object) {
		this.data=name;
	} else {
		this.data[name] = value;
	}
};

AbstractChartSeries.prototype.getConfig = function() {
	if (name) {
		return this.data[name];
	} else {
		return this.data;
	}
};

  /*----------------------------------------------------------------------------\
  |                              BarChartSeries                                 |
  |- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -|
  | Bar Chart Series                                                            |
  \----------------------------------------------------------------------------*/

function BarChartSeries(data) {
	// data hash contains keys
	var defaultData = {
		label:"BarChart",// label - name of series
		color:"#000",    // color - HTML color for series
		values:[],       // values - array of values
		distance:0,      // distance - Sets distance between bars for bar charts.
		width:10,        // width - Sets with of bars for bar charts
		offset:0,        // offset - index of the bar in the chart
	};
	for (var p in data) {defaultData[p]=data[p];}
	this.data=defaultData;
	this.base=AbstractChartSeries;
	this.offset = this.data['distance'] + this.data['offset'] * (this.data['width'] + this.data['distance']);
}

BarChartSeries.prototype=new AbstractChartSeries;

BarChartSeries.prototype.draw = function(chart) {
	// draws a bar chart
    var i, len, x, y, barHt, yBottom, n, yoffset,painter,values;
	painter=chart.getPainter();
	values=this.getStackedValues(chart);
    if (values.length<=0) return;
    /* Determine distance between points and offset */
    n = chart.range / chart.charth;
    yoffset = (chart.ymin / n);
	yBottom = chart.charty + chart.charth + yoffset;
	
    len = values.length;
    if (len > chart.xlen) { len = chart.xlen; }
    if (len) {
		/* Determine position of each bar and draw it */
		x = chart.chartx + this.offset + 1;
		for (i = 0; i < len; i++) {
			y = (values[i] / n);
			barHt = (this.data['values'][i] / n);
			painter.fillRect(this.data['color'],x,yBottom-y,this.data['width'],barHt);
			x += chart.xstep;
		}
    }
};

  /*----------------------------------------------------------------------------\
  |                              AreaChartSeries                                 |
  |- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -|
  | Area Chart Series                                                            |
  \----------------------------------------------------------------------------*/

function AreaChartSeries(data) {
	// data hash contains keys
	var defaultData = {
		label:"AreaChart",// label - name of series
		color:"#000",    // color - HTML color for series
		values:[],       // values - array of values
	};
	for (var p in data) {defaultData[p]=data[p];}
	this.data=defaultData;
	this.base=AbstractChartSeries;
}

AreaChartSeries.prototype=new AbstractChartSeries;

AreaChartSeries.prototype.draw = function(chart) {
	// draws a bar chart
    var i, len, x, y, barHt, yBottom, n, yoffset,painter,values;
	var points=[];
	painter=chart.getPainter();
	values=this.getStackedValues(chart);
    if (values.length<=0) return;
    /* Determine distance between points and offset */
    n = chart.range / chart.charth;
    yoffset = (chart.ymin / n);
	yBottom = chart.charty + chart.charth + yoffset;

    /* Begin line in lower left corner */
    points.push({x:chart.chartx + 1,y:chart.charty + chart.charth - 1});
	
    len = values.length;
    if (len > chart.xlen) { len = chart.xlen; }
    if (len) {
		/* Determine position of each bar and draw it */
		for (i = 0; i < len; i++) {
			y = (values[i] / n);
			barHt = (this.data['values'][i] / n);
			points.push({x:chart.chartx + 1 + chart.xstep*i,y:yBottom-y});
		}
		/* Add end point at lower right corner */
		points.push({x:chart.chartx + 1 + chart.xstep*(len-1),y:chart.charty + chart.charth - 1});
		for (i = len-1; i >=0; i--) {
			y = (values[i] / n);
			barHt = (this.data['values'][i] / n);
			points.push({x:chart.chartx + 1 + chart.xstep*i,y:yBottom-y+barHt});
		}
		painter.fillArea(this.data['color'],points);
    }
};


  /*----------------------------------------------------------------------------\
  |                              LineChartSeries                                |
  |- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -|
  | Line Chart Series                                                           |
  \----------------------------------------------------------------------------*/

function LineChartSeries(data) {
	// data hash contains keys
	var defaultData = {
		label:"LineChart",// label - name of series
		color:"#000",    // color - HTML color for series
		values:[],       // values - array of values
	};
	for (var p in data) {defaultData[p]=data[p];}
	this.data=defaultData;
	this.base=AbstractChartSeries;
}

LineChartSeries.prototype=new AbstractChartSeries;

LineChartSeries.prototype.draw = function(chart) {
    var i, len, x, y, n, yoffset;
	painter=chart.getPainter();
	values=this.getStackedValues(chart);
    if (values.length<=0) return;
    var points=[];
    /* Determine distance between points and offset */
    n = chart.range / chart.charth;
    yoffset = (chart.ymin / n);

    /* Add points */
    for (i=0;i <values.length;i++) {
		points.push({x:chart.chartx+1+i*chart.xstep,y:chart.charty + chart.charth - (values[i] / n) + yoffset});
    }
    painter.polyLine(this.data['color'],1,points);
};



	
/*----------------------------------------------------------------------------\
  |                            AbstractChartPainter                             |
  |- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -|
  | Abstract base class defining the painter API. Can not be used directly.     |
  \----------------------------------------------------------------------------*/

function AbstractChartPainter() {

};


AbstractChartPainter.prototype.create = function(el) {};
AbstractChartPainter.prototype.getWidth = function() {
    return this.w;
};

AbstractChartPainter.prototype.getHeight = function() {
    return this.h;
};

AbstractChartPainter.prototype.fillArea = function(color, points) {};
AbstractChartPainter.prototype.polyLine = function(color,lineWidth,points) {};
AbstractChartPainter.prototype.fillRect = function(color, x,y,width,height) {};
AbstractChartPainter.prototype.line = function(color,lineWidth,x1,y1,x2,y2) {};
