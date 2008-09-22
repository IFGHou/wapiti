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

function Chart(el,config) {
	this._cont             = el;
	this._series           = new Array();
	this._painter          = null;
	var defaultConfig = {
		yMin:0,
		yMax:0,
		xGrid:0,
		yGrid:10,
		labelPrecision:0,
		showLegend:true,
		xLabels:new Array(),
		painterType:'canvas',
		legendWidth:150,
		backgroundColor:'white',
		gridColor:'silver',
		axesColor:'black',
		textColor:'black'
	};
	for (var p in config) {if (config[p] !='') defaultConfig[p]=config[p];}
	this.config=defaultConfig;

	/*
	 * Determine painter implementation to use based on what's available and
	 * supported. CanvasChartPainter is the prefered one, JsGraphicsChartPainter
	 * the fallback one as it works in pretty much any browser. The
	 * SVGChartPainter implementation one will only be used if set explicitly as
	 * it's not up to pair with the other ones.
	 */
	if (this.config.painterType == 'canvas') {
		try {
			this.setPainterFactory(CanvasChartPainterFactory);
		} catch(e) {
			alert("Canvas painter not loaded");
		}
	} else if (this.config.painterType == 'jsgraphics') {
		try {
		this.setPainterFactory(JsGraphicsChartPainterFactory);
		} catch(e) {
			alert("JSGraphics painter not loaded");
		}
	} else {
		try {
			this.setPainterFactory(CanvasChartPainterFactory);
		} catch(e) {
			try {
				this.setPainterFactory(JsGraphicsChartPainterFactory);
			} catch(e1) {
				alert("No supported painter factory found");
			}
		}
	}

	if (!this._painter) { return; }

	/* Initialize chart range */
	this.xlen = this.config.xLabels.length; /* number of x ticks */
	this.ymin = this.config.yMin; /* min y value */
	this.ymax = this.config.yMax; /* max y value */

	/* Initialize painter object */
    this.w=this._painter.getWidth();
    this.h=this._painter.getHeight();
    this.chartx = 0;
    this.charty = 0;
    this.chartw	= this.w;
    this.charth	= this.h;
	
	/* Initialize bar offset to 0 */
	this.offset=0;

}

/*
 * Function for ChartSeries objects to retrieve painter from Chart 
 */
Chart.prototype.getPainter = function() {
	return this._painter;
};


/*
 * Function to add a ChartSeries object to the Chart 
 */
Chart.prototype.add = function(series) {
	try {
		// is it a valid ChartSeries object?
		series.getLabel();
	} catch(e) {
		// no... has a type been defined?
		try {
			series=eval("new "+series.type+"ChartSeries(series);");
		}catch(e1) {
			alert(e);
		}
	}
	this._series.push(series);
	/* Adjust the Chart range in case the series has values outside the chart */
	var range=series.getRange(this);
	/* Calculate y range and xstep in case the range changed*/
    this.adjustRange(range);
	/* Do we need to increment the offset? required for bar charts */
	if (series.toOffset()) {
		this.offset++;
	}
};


/*
 * Function to draw one or all Chart Series. 
 */
Chart.prototype.draw = function(seriesLabel) {

	if (!this._painter) { return; }

	if (typeof seriesLabel != 'undefined') {
		var series=this.find(seriesLabel);
		if (series) {
			series.draw(this);
			if (this.config.showLegend) { this.drawLegend(series); }
		}
	} else {
		/* Draw all series */
		for (var i = 0; i < this._series.length; i++) {
			this._series[i].draw(this);
			if (this.config.showLegend) {this.drawLegend(this._series[i])};
		}
	}

	/*
	 * Draw axes (after the series since the anti aliasing of the lines may
	 * otherwise be drawn on top of the axis)
	 */
	this.drawAxes();

};


/*
 * Function to find a ChartSeries from the Chart by specifying the series label
 */
Chart.prototype.find = function(label) {
    for (var i = 0; i < this._series.length; i++) {
		if (this._series[i].getLabel()==label) {
			return this._series[i];
		}
	}
	return null;
};

/*
 * function to clear chart background and draw grid, legend
 * Draws the chart grid and labels
 */
Chart.prototype.clear = function() {


	/*
	 * Create legend div
	 */
	if (this.config.showLegend) {
		this.createLegend();
	}

	/* clear background with white */
    this._painter.fillRect(this.config.backgroundColor,0, 0, this.w, this.h);

	/* Set xGrid to xlen in case it is not specified in config */
	if (this.config.xGrid<=this.xlen-1) {
		this.config.xGrid=this.xlen-1;
	}
	this.adjustRange();
	/*
	 * draw labels
	 */
	if (this.showLabels) {
	    this.drawVerticalLabels();
	    this.drawHorizontalLabels();
	}
	/*
	 *  draw grid
	 */
    if (this.xGridDensity) {
		for (var i = 0; i < this.config.xGrid; i++) {
			var x=1+this.chartx+(i*this.xGridDensity);
			this._painter.line(this.config.gridColor,1,x, this.charty, x, this.charty + this.charth);
		}
		this._painter.line(this.config.gridColor,1,this.chartx+this.chartw, this.charty, this.chartx+this.chartw, this.charty + this.charth);
    }
    if (this.yGridDensity) {
		for (var i = 0; i < this.config.yGrid; i++) {
			var y=this.charty+this.charth - (i*this.yGridDensity)-1;
			this._painter.line(this.config.gridColor,1,this.chartx + 1,y, this.chartx + this.chartw + 1,y);
		}
		this._painter.line(this.config.gridColor,1,this.chartx+1, this.charty, this.chartx+this.chartw, this.charty);
    }
	this.adjustRange();
	/* draw axes */
	this.drawAxes();

};


/*
 * Internal function for setting the painter factory
 */
Chart.prototype.setPainterFactory = function(f) {
	this._painterFactory = f;
	/* Create painter object */
	this._painter = this._painterFactory();
	this._painter.create(this._cont);
    this._painter.fillRect(this.config.backgroundColor,0, 0, 1, 1);
};

/*
 * Internal function to calculate chart range
 */
Chart.prototype.adjustRange = function(range) {
	if (typeof range != 'undefined') {
		if (range.xlen > this.xlen) { this.xlen = range.xlen; }
		if (range.ymin < this.ymin) {this.ymin=range.ymin;}
		if (range.ymax > this.ymax) {this.ymax=range.ymax;}
	}
    this.range = this.ymax - this.ymin;
    this.xstep = this.chartw / (this.xlen - 1);
	/*
	 * Determine whatever or not to show the legend and axis labels
	 * Requires density and labels to be set.
	 */
	this.xGridDensity=0;
	this.yGridDensity=0;
	if (this.config.xGrid>0) {
		this.xGridDensity=Math.round((this.chartw-1)/this.config.xGrid);
	}
	if (this.config.yGrid>0) {
		this.yGridDensity=Math.round((this.charth-1)/this.config.yGrid);
	}
	this.showLabels = (this.xGridDensity) && (this.yGridDensity);

};

/*
 * Internal function to draw chart axes
 */
Chart.prototype.drawAxes = function() {
    var x1 = this.chartx;
    var x2 = this.chartx + this.chartw + 1;
    var y1 = this.charty;
    var y2 = this.charty + this.charth - 1;
    this._painter.line(this.config.axesColor,1,x1, y1, x1, y2);
    this._painter.line(this.config.axesColor,1,x1, y2, x2, y2);
};

/*
 * Internal function to create the chart legend div
 */
Chart.prototype.createLegend = function() {
	var series=this._series;
    this.legend = document.createElement('div');
    this.legend.style.position = 'absolute';
    this.legendList = document.createElement('ul');
	this.legendList.style.listStyle='square';
	this.legend.style.backgroundColor=this.config.backgroundColor;
    this.legend.style.width = this.config.legendWidth+'px';
    this.legend.style.right = '0px';
	this.legend.style.border='1px solid '+this.config.textColor;
	this.legend.style.borderColor=this.config.textColor;
    this.legend.style.top  = this.charty + (this.charth / 2) - (this.legend.offsetHeight / 2) + 'px';
    this.legend.appendChild(this.legendList);
    this._cont.appendChild(this.legend);
    /* Recalculate chart width and position based on labels and legend */
    this.chartw	= this.w - (this.config.legendWidth + 5);
    this.adjustRange();
};

/*
 * Internal function to draw the legend for a series
 */
Chart.prototype.drawLegend = function(series) {
	if (typeof series == 'undefined') {
		for(var i=0;i<this._series.length;i++) {
			this.drawLegend(this._series[i]);
		}
		return;
	}
	this.legendList.innerHTML+='<li style="color:'+series.getColor()+'"><span style="color:'+this.config.textColor+'">'+series.getLabel()+'</span>';
	/*******
	item = document.createElement('li');
	item.style.color = series.getColor();
	label = document.createElement('span');
	label.appendChild(document.createTextNode(series.getLabel()));
	label.style.color = 'black';
	item.appendChild(label);
	this.legendList.appendChild(item);
	********/
};

/*
 * Internal function to draw vertical labels and ticks
 */
Chart.prototype.drawVerticalLabels = function() {
    var axis, item, step, y, ty, n, yoffset, value, multiplier, w, items, pos;
	var ygd, precision;
	ygd=this.config.yGrid;
	if (ygd<=0) return;
	precision=this.config.labelPrecision;
    /* Calculate step size and rounding precision */
    multiplier = Math.pow(10, precision);
    step       = this.range / this.config.yGrid;

    /* Create container */
	//axis=jQuery(this._cont).append('<div style="position:absolute;left:0;top:0;text-align:right"></div>').get(0);
    axis = document.createElement('div');
    axis.style.position = 'absolute';
    axis.style.left  = '0px';
    axis.style.top   = '0px';
    axis.style.textAlign = 'right';
    this._cont.appendChild(axis);
	
    /* Draw labels and points */
    w = 0;
    items = new Array();
    for (i=0;i<=this.config.yGrid;i++) {
		value = parseInt((this.ymin+(i*step)) * multiplier) / multiplier;
		//item=jQuery(axis).append('<span>'+value+'</span>').get(0);
		item = document.createElement('span');
		item.appendChild(document.createTextNode(value));
		axis.appendChild(item);
		items.push(item);
		if (item.offsetWidth > w) { w = item.offsetWidth; }
    }
	
    /* Draw last label and point (lower left corner of chart) */
    item = document.createElement('span');
    item.appendChild(document.createTextNode(this.ymin));
    axis.appendChild(item);
    items.push(item);
    if (item.offsetWidth > w) { w = item.offsetWidth; }
	
    /* Set width of container to width of widest label */
    axis.style.width = w + 'px';
	
    /* Recalculate chart width and position based on labels and legend */
    this.chartx = w + 5;
    this.charty = item.offsetHeight / 2;
    this.charth = this.h - ((item.offsetHeight * 1.5) + 5);
    this.chartw	= this.w - (((this.legend)?this.legend.offsetWidth:0) + w + 10);
    this.adjustRange();
	
    /* Position labels on the axis */
    for (i = 0; i < items.length; i++) {
		y=this.charty+this.charth-(i*this.yGridDensity);
		ty=this.charth-(i*this.yGridDensity);
		item = items[i];
		this._painter.fillRect(this.config.textColor,this.chartx - 5, y, 5, 1);
		item.style.position = 'absolute';
		item.style.right = '0px';
		item.style.top   = ty + 'px';
		item.style.color=this.config.textColor;
    }	
};


/*
 * Internal function to draw horixontal labels and ticks
 */
Chart.prototype.drawHorizontalLabels = function() {
    var axis, item, step, x, tx;
	var xlen, labels, xgd, precision;
	labels=this.config.xLabels;

    /* Create container */
    axis = document.createElement('div');
    axis.style.position = 'absolute';
    axis.style.left   = '0px';
    axis.style.top    = (this.charty + this.charth + 5) + 'px';
    axis.style.width  = this.w + 'px';
    this._cont.appendChild(axis);

    /* Draw labels and points */
	x = this.chartx;
    for (i = 0; i < this.xlen; i++) {
		item = document.createElement('span');
		if (labels[i]) {
			item.appendChild(document.createTextNode(labels[i]));
		}
		axis.appendChild(item);
		tx = x - (item.offsetWidth/2);
		item.style.position = 'absolute';
		item.style.left = tx + 'px';
		item.style.top  = '0px';
		item.style.color=this.config.textColor;
		this._painter.fillRect(this.config.textColor,x, this.charty + this.charth, 1, 5);
		x += this.xstep;
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
	return this.config.color;
};
	
AbstractChartSeries.prototype.getLabel = function() {
	return this.config.label;
};

AbstractChartSeries.prototype.getRange = function(chart) {
	var i,ymin,ymax,xlen;
	var values=this.getStackedValues(chart);
	xlen=values.length;
	ymin=values[0];
	ymax=ymin;
	for (i = 0; i < this.config.values.length; i++) {
		ymin=Math.min(values[i],ymin);
		ymax=Math.max(values[i],ymax);
	}
	return {xlen:xlen,ymin:ymin,ymax:ymax};
};

AbstractChartSeries.prototype.toOffset = function() {
	return 0;
};

AbstractChartSeries.prototype.getStackedValues = function(chart) {
	var stacked=new Array();
	if (this.config.stackedOn) {
		var stackedSeries=chart.find(this.config.stackedOn);
		if (stackedSeries) {
			stacked=stackedSeries.getStackedValues(chart);
		}
	}
	for(var i=0;i<this.config.values.length;i++) {
		if (stacked[i]) {
			stacked[i]=parseFloat(stacked[i])+parseFloat(this.config.values[i]);
		} else {
			stacked[i]=this.config.values[i];
		}
	}
	return stacked;
};

AbstractChartSeries.prototype.setConfig = function(name,value) {
	if (!value && typeof name == Object) {
		this.config=name;
	} else {
		this.config[name] = value;
	}
};

AbstractChartSeries.prototype.getConfig = function() {
	if (name) {
		return this.config[name];
	} else {
		return this.config;
	}
};

  /*----------------------------------------------------------------------------\
  |                              BarChartSeries                                 |
  |- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -|
  | Bar Chart Series                                                            |
  \----------------------------------------------------------------------------*/

function BarChartSeries(config) {
	// config hash contains keys
	var defaultConfig = {
		label:"BarChart",// label - name of series
		color:"#000",    // color - HTML color for series
		values:[],       // values - array of values
		distance:0,      // distance - Sets distance between bars for bar charts.
		width:10,        // width - Sets with of bars for bar charts
		offset:0        // offset - index of the bar in the chart
	};
	for (var p in config) {defaultConfig[p]=config[p];}
	this.config=defaultConfig;
	this.offset=0;
}

BarChartSeries.prototype=new AbstractChartSeries;

BarChartSeries.prototype._getRange=AbstractChartSeries.prototype.getRange;
BarChartSeries.prototype.getRange = function(chart) {
	var range=this._getRange(chart);
	range.xlen++;
	if (chart.offset && (!this.config.stackedOn || this.config.stackedOn=='')) {
		this.offset = this.config.distance + chart.offset * (this.config.width + this.config.distance);
	} else {
		if (this.config.stackedOn) {
			var stackedOn=chart.find(this.config.stackedOn);
			if (stackedOn) {
				this.offset=stackedOn.offset;
			}
		}
	}
	return range;
};

BarChartSeries.prototype.toOffset = function() {
	return (!this.config.stackedOn || this.config.stackedOn=='')?1:0;
};

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
			barHt = (this.config.values[i] / n);
			painter.fillRect(this.config.color,x,yBottom-y,this.config.width,barHt);
			x += chart.xstep;
		}
    }
};

  /*----------------------------------------------------------------------------\
  |                              AreaChartSeries                                 |
  |- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -|
  | Area Chart Series                                                            |
  \----------------------------------------------------------------------------*/

function AreaChartSeries(config) {
	// config hash contains keys
	var defaultConfig = {
		label:"AreaChart",// label - name of series
		color:"#000",    // color - HTML color for series
		values:[]       // values - array of values
	};
	for (var p in config) {defaultConfig[p]=config[p];}
	this.config=defaultConfig;
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
			barHt = (this.config.values[i] / n);
			points.push({x:chart.chartx + 1 + chart.xstep*i,y:yBottom-y});
		}
		/* Add end point at last value height, right edge */
		points.push({x:chart.chartx+chart.chartw,y:yBottom-y});
		/* Add end point at lower right corner */
		points.push({x:chart.chartx+chart.chartw,y:yBottom-y+barHt});
		for (i = len-1; i >=0; i--) {
			y = (values[i] / n);
			barHt = (this.config.values[i] / n);
			points.push({x:chart.chartx + 1 + chart.xstep*i,y:yBottom-y+barHt});
		}
		painter.fillArea(this.config.color,points);
    }
};


  /*----------------------------------------------------------------------------\
  |                              LineChartSeries                                |
  |- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -|
  | Line Chart Series                                                           |
  \----------------------------------------------------------------------------*/

function LineChartSeries(config) {
	// config hash contains keys
	var defaultConfig = {
		label:"LineChart",// label - name of series
		lineWidth:2,          // line width
		color:"#000",    // color - HTML color for series
		values:[]       // values - array of values
	};
	for (var p in config) {defaultConfig[p]=config[p];}
	this.config=defaultConfig;
	this.base=AbstractChartSeries;
}

LineChartSeries.prototype=new AbstractChartSeries;

LineChartSeries.prototype.draw = function(chart) {
    var i, len, x, y, n, yoffset,yBottom;
	painter=chart.getPainter();
	values=this.getStackedValues(chart);
    if (values.length<=0) return;
    var points=[];
    /* Determine distance between points and offset */
    n = chart.range / chart.charth;
    yoffset = (chart.ymin / n);
	yBottom = chart.charty + chart.charth + yoffset;

    /* Add points */
	y=0;
    for (i=0;i <values.length;i++) {
		y = (values[i] / n);
		points.push({x:chart.chartx+1+i*chart.xstep,y:yBottom-y});
    }
	/* Add end point at last value height, right edge */
	points.push({x:chart.chartx+chart.chartw,y:yBottom-y});
    painter.polyLine(this.config.color,this.config.lineWidth,points);
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
