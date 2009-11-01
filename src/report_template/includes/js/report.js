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
    str = str.replace(/&/g, "&amp;");
    str = str.replace(/>/g, "&gt;");
    str = str.replace(/</g, "&lt;");
    str = str.replace(/"/g, "&quot;");
    str = str.replace(/'/g, "&#039;")
    return str;
/* Does not convert quotes
    var el = document.createElement("div");
    el.innerText = el.textContent = s;
    s = el.innerHTML;
    delete el;
    return s;
*/
}

function processTextForLink(str)
{
    return str.replace(/[ ]/g, "_");
}

function processTextForCharts(str)
{
    return str.replace(/[ ]/g, "+");
}

$(document).ready(function() {
    var vulnerabilities_table = new Object();
    var vulnerability_names = [];

    $.ajax({
        type: "GET",
        url: "vulnerabilities.xml",
        dataType: "xml",
        ayncr: false,
        success: function(xml) {
            var y = 0;
            $(xml).find('bugType').each(function (i){
                id = 'vul'+(++y);
                vulnerability_names[id] = $(this).attr('name');
                vulnerabilities_table [id] = new Array (3);
                for (i=0; i<3; i++)
                    vulnerabilities_table [id][i]= 0;
                $('#vulnerabilities_table').append("<div name=\""+processTextForLink(id)+"\" id='"+processTextForLink(id)+"'><h3><img id='img_"+processTextForLink(id)+"' src='includes/images/collapse.gif' /> "+vulnerability_names[id]+"</h3></div>");
                $('#vulnerabilities_table').append("<div id='div_"+processTextForLink(id)+"'>");
                linkId = "#"+processTextForLink(id);
                divId = "#div_"+processTextForLink(id);
                $(linkId).click(function(){ toggle(this.id);});

                description =  $(this).find('description').text();
                solution =  $(this).find('solution').text();
                references = "<ul>"
                $(this).find('references').each( function (m){
                    $(this).find('reference').each( function (m){
                        references += "<li><a href='"+$(this).find('url').text()+"'>"+$(this).find('title').text()+"</a></li>"
                    });
                });
                references += "</ul>"

                vulnerability_body = "";

                $(this).find ('bug').each ( function (v){
                    level = $(this).attr('level');
                    vulnerabilities_table[id][level-1]++;
                    url = $(this).find('url').text();
                    url = cleanHTMLTags(url);
                    parameter = $(this).find('parameter').text();
                    parameter = cleanHTMLTags(parameter);
                    info = $(this).find('info').text();
                    //info = cleanHTMLTags(info);
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
                    vulnerability_body = vulnerability_body+"<table class='vulnerability'><tr><td style='background:"+color+"'>Risk Level</td><td style='background:"+color+"'>"+riskLevel+"</td></tr><tr><td class='table_title'>Url</td><td><a href='"+url+"'>"+url+"</a></td></tr><tr><td class='table_title'>Parameter</td><td>"+parameter+"</td></tr><tr><td class='table_title'>Info</td><td >"+info+"</td></tr></table><br/>";

                });



                var vulnerabilityFound = false;
                for (i=0; i<3; i++)
                {
                    if(vulnerabilities_table [id][i] != 0)
                    {
                        vulnerabilityFound = true
                        break;
                    }
                }
                if(vulnerabilityFound == false)
                    $(divId).append("<b>No vulnerabilities found</b><br/>");
                else
                    $(divId).append("<table><tr><td><b>Description:</b></td><td>"+description+"</td></tr><tr><td><b>Solution:</b></td><td>"+solution+"</td><tr><td><b>References:</b></td><td>"+references+"</td></tr></table><br/>"+vulnerability_body);

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
                header += "<th><a href=\"#"+k+"\">"+vulnerability_names[k]+" ("+(v+1)+") </a></th>";
                vuln_names[v] = vulnerability_names[k];
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

            //Scale
            var scale_string="|1:|0|";
            yMax = 100;

            if (max < 5){
                yMax = 5;
                scale_string = scale_string + "1|2|3|4|5";
            }
            else if (max < 10){
                yMax =10;
                 scale_string = scale_string + "1|2|3|4|5|6|7|8|9|10";
            }
            else if (max < 25){
                yMax = 25;
                scale_string = scale_string + "5|10|15|20|25";
            }
            else if (max < 50){
                yMax = 50;
                scale_string = scale_string + "5|10|15|20|25|30|35|40|45|50";
            }
            else if (max < 100){
                yMax = 100;
                scale_string = scale_string + "10|20|30|40|50|60|70|80|90|100";
            }
            else{
                yMax = max;
                scale_string = scale_string + Math.floor(yMax/4)+"|"+Math.floor(yMax/2)+"|"+Math.floor((yMax/4)*3)+"|"+yMax;
            }


            //Draw the Chart using Google Charts (http://code.google.com/apis/chart/)
            var base_url = "http://chart.apis.google.com/chart?chtt=Summary&chts=000000,12&chs=700x200&chf=bg,s,ffffff|c,s,ffffff&chxt=x,y&chxl=0:";
            var vuln_names_string = "";
            var data_string = "&cht=bvg&chd=t:";
            var base_url_end = "&chdl=Low|Medium|High&chco=ffff33,ff9933,ff0000&chbh=25";

            //Vulnerability names
            for (i=0; i<vuln_names.length; i++)
                vuln_names_string = vuln_names_string + "|" +(i+1);


            //Data format
            for (i=2; i>-1; i--){
                for (j=0; j<vuln[i].length; j++){
                    var num = (vuln[i][j]*100)/yMax;
                    data_string = data_string + num;
                    if (j != (vuln[i].length -1))
                        data_string = data_string +",";
                }
                if (i != 0)
                    data_string = data_string +"|";
            }

            var url_google_chart = base_url + vuln_names_string + scale_string + data_string + base_url_end;
            $('#mychart').append("<img src='"+url_google_chart+"' alt='Summary Chart' />");

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
