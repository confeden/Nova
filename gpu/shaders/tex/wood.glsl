// Wood: growth rings born at ONE pith and running outward. The pith wanders slowly along a smooth random path (its start
// is random per seed), so the centre moves gradually across the picture and there is never a second centre.
void tex(vec2 p,float t,out vec3 alb,out vec3 emi,out float den,out float h){
 vec2 c0=vec2(1.3*(vn(vec2(t*.011+uSeed*1.7,3.1))+.5*vn(vec2(t*.027+uSeed,8.3))-.75),.9*(vn(vec2(t*.009+uSeed*.9,17.7))+.5*vn(vec2(t*.023+uSeed*2.1,5.9))-.75));
 vec2 d=p-c0;d+=.05*vec2(fbm(p*2.5+S+3.),fbm(p*2.5+S+8.));
 float r=length(d*vec2(1.,1.22));vec2 dn=d/max(length(d),1e-4);float lr=log(r+.06);                                                        // bounded ring density: log(r) piled up infinitely many rings at the pith (moire)
 float aa=1.-smoothstep(.07,.2,7.5/(r+.06)/uRes.y);                  // rings closer than ~6 px fade to their mean tone instead of aliasing
 float rr=lr*7.5-t*.26+.4*fbm(dn*1.7+lr*.8+S);
 float fr=fract(rr);float id=mix(.5,vn(vec2(rr*.5,5.)),aa);
 float ring=mix(.72,smoothstep(0.,.8,fr)*smoothstep(1.,.92,fr),aa);
 float line=smoothstep(.10,0.,abs(fract(rr+.54)-.5))*aa;
 float fibre=mix(.45,fbm(dn*36.+lr*2.)*.6+.4*fbm(vec2(lr*40.,dn.x*3.+dn.y*5.)),aa);
 float core=smoothstep(.0,.07,r);
 h=(.3+.4*ring+.15*fibre)*core;
 alb=mix(vec3(.15,.07,.03),vec3(.68,.41,.18),ring*.7+fibre*.3)*(.75+.45*id);
 float s2=2.*dn.x*dn.y,c2=dn.x*dn.x-dn.y*dn.y;float ct=cos(t*1.1+id*30.),st=sin(t*1.1+id*30.);
 float sap=pow(.5+.5*(s2*ct+c2*st),3.)*smoothstep(.45,.65,id);
 emi=mix(vec3(1.,.5,.12),pal(id+.1),.5)*line*(.45+3.*sap)*core+vec3(1.,.6,.2)*(1.-core)*1.5;
 den=12.+25.*line;}
