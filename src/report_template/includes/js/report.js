/* Wapiti v1.1.8 alpha- Html view generator
 * 
 * Alberto Pastor
 * David del Pozo
 * Copyright (C) 2008 Informatica Gesfor
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

 
function cleanHTMLTags(str)
    {
        return str.replace("<", "&lt;", 'g').replace(">", "&gt;", 'g');
    }

    function processTextForLink(str)
    {
        return str.replace(/[ ]/g, "_");
    }

    $(document).ready(function() {

    var vulnerabilities_table = new Object();

    $.ajax({
                    type: "GET",
                    url: "vulnerabilities.xml",
                    dataType: "xml",
                    ayncr: false,
                    success: function(xml) {
                            $(xml).find('vulnerabilityType').each(function (i){
                                    name = $(this).attr('name');
                                    vulnerabilities_table [name] = new Array (3);
                                    for (i=0; i<3; i++)
                                            vulnerabilities_table [name][i]= 0;
                                    $('#vulnerabilities_table').append("<div name=\""+processTextForLink(name)+"\" id='"+processTextForLink(name)+"'><h3><img id='img_"+processTextForLink(name)+"' src='includes/images/collapse.gif' /> "+name+"</h3></div>");
				    $('#vulnerabilities_table').append("<div id='div_"+processTextForLink(name)+"'>");
				    linkId = "#"+processTextForLink(name);
				    divId = "#div_"+processTextForLink(name);
				    $(linkId).click(function(){ toggle(this.id);});


				    description =  $(this).find('description').text();
				    solution =  $(this).find('solution').text();
				    references =  $(this).find('references').text();
				    $(divId).append("<table><tr><td><b>Description:</b></td><td>"+description+"</td></tr><tr><td><b>Solution:</b></td><td>"+solution+"</td><tr><td><b>References:</b></td><td>"+references+"</td></tr></table><br/>");


                                    $(this).find ('vulnerability').each ( function (v){
                                            level = $(this).attr('level');
                                            vulnerabilities_table[name][level-1]++;
                                            url = $(this).find('url').text();
                                            url = cleanHTMLTags(url);
                                            parameter = $(this).find('parameter').text();
                                            parameter = cleanHTMLTags(parameter);
                                            info = $(this).find('info').text();
                                            info = cleanHTMLTags(info);
					    color="";
					    riskLevel = "";
					    if (level == "1"){
						color= "#fb1414";
						riskLevel = "High";
					    }else if (level =="2"){
						color="#f3bf21";
						riskLevel = "Medium";
				            }else if (level == "3"){
						color="#f1f321";
						riskLevel = "Low";
					    }
                                            $(divId).append("<table class='vulnerability'><tr><td style='background:"+color+"'>Risk Level</td><td style='background:"+color+"'>"+riskLevel+"</td></tr><tr><td class='table_title'>Url</td><td>"+url+"</td></tr><tr><td class='table_title'>Parameter</td><td>"+parameter+"</td></tr><tr><td class='table_title'>Info</td><td >"+info+"</td></tr></table><br/>");

                                    });

                                    var vulnerabilityFound = false;
                                    for (i=0; i<3; i++)
                                    {
                                        if(vulnerabilities_table [name][i] != 0)
                                        {
                                            vulnerabilityFound = true
                                            break;
                                        }
                                    }
                                    if(vulnerabilityFound == false)
                                        $('#vulnerabilities_table').append("<b>No vulnerabilities found</b><br/>");
			            $('#vulnerabilities_table').append("</div>");
	
                            });

                            //Draw the result table
                            header = "<thead><td></td>";
                            body = "<tbody>";
                            var max = 1;
                            var row = new Array(3);
                            row [0] = "<tr><th headers='members' id='high'>High</th>";
                            row [1] = "<tr><th headers='members'id='medium'>Medium</th>";
                            row [2] = "<tr><th headers='members'id='low'>Low</th>";
                            var vuln_names = [];
                            var vuln = [];
                            vuln [0] = [];
                            vuln [1] = [];
                            vuln [2] = [];
                            var v = 0;
                            for (var k in vulnerabilities_table){
                                    header += "<th id='"+k+"'><a href=\"#"+processTextForLink(k)+"\">"+k+"</a></th>";
                                    vuln_names[v] = k;
                                    for (i=0; i<3; i++){
                                            row[i] += "<td headers='"+k+"'>"+vulnerabilities_table[k][i]+"</td>";
                                            vuln[i][v]= vulnerabilities_table[k][i];
                                            if (vulnerabilities_table[k][i] > max)
                                                    max = vulnerabilities_table[k][i];
                                    }		
                                    v++
                            }
                            for (i=0; i<3; i++)
                                    body += row[i]+"</tr>";
                            header += "</thead>";
                            body += "</tbody>";
                            $('#result_table').append("<table id='dataTable' >"+header+body+"</table>");
				
					
			if (max < 5)
				yGrid = yMax = 5;
			else if (max < 10)
				yGrid = yMax =10;
			else if (max < 25){
				yMax = 25;
				yGrid = 5;
			}
			else if (max < 50){
				yMax = 50;
				yGrid = 10;
			}
			else if (max < 100){
				yMax = 100;
				yGrid = 10;
			}
			else{
				yMax = max;
				yGrid = max/10;
			}
                            $('#mychart').chartInit({"painterType":"canvas","backgroundColor":"","textColor":"","axesColor":"","yMin":"0","yMax":yMax ,"xGrid":"0","yGrid":yGrid,"xLabels":vuln_names,"showLegend":false})
    .chartAdd({"label":"High","type":"Bar","color":"#fb1414","values":vuln[0]})
    .chartAdd({"label":"Medium","type":"Bar","color":"#f3bf21","values":vuln[1],"stackedOn":""})
    .chartAdd({"label":"Low","type":"Bar","color":"#f1f321","values":vuln[2],"stackedOn":""})
    .chartClear()
    .chartDraw();
                    }
            });
    });

    function toggle(id){
		divId = "#div_"+id;
		imgId = "#img_"+id;
		if ($(imgId).attr('src') == "includes/images/collapse.gif")
			$(imgId).attr('src', "includes/images/expand.gif");
		else
			$(imgId).attr('src', "includes/images/collapse.gif");
		$(divId).toggle();
	}