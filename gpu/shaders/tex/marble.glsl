void tex(vec2 p,float t,out vec3 alb,out vec3 emi,out float den,out float h){
 vec2 q=p*2.2+S+vec2(t*.012,t*.007);vec2 w=vec2(fbm(q+t*.035),fbm(q+5.2-t*.028));vec2 w2=vec2(fbm(q+4.*w+1.7),fbm(q+4.*w+9.2));
 float f=fbm(q+3.*w2);
 float v=pow(1.-abs(sin((q.x+q.y*.6+f*5.)*3.1416)),14.);
 float v2=pow(1.-abs(sin((f*9.+q.y)*3.1416)),30.);
 float v3=pow(1.-abs(sin((f*23.+w2.x*6.)*3.1416)),40.);
 h=f*.6+.2-v*.3;
 alb=mix(vec3(.34,.34,.40),vec3(.85,.86,.9),f)*mix(vec3(1),pal(f+.3),.3);
 emi=pal(f*1.5+length(w2))*(v*2.6+v2*1.3)+pal(f*2.+.5)*v3*.5;
 den=6.+v*30.;}