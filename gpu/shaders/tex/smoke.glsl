// Smoke: rolling billows. Turbulence (|2n-1| octaves) gives round, creased puffs; the field is domain-warped by a slow
// swirl and rises; three scales are crossfaded for an endless dive into the plume. Grey bodies lit from below by a warm
// glow tinted by the accent, dark creases between the puffs. Relief comes from the height (light upper-left), so the
// billows read as volumes, not as coloured bands.
float turb(vec2 p){float a=.5,s=0.;for(int i=0;i<6;i++){s+=a*abs(2.*vn(p)-1.);p=mat2(1.6,1.2,-1.2,1.6)*p+vec2(1.7,9.2);a*=.5;}return s;}
float puff(vec2 q,float t,float A){
 vec2 sw=vec2(fbm(q*.5+vec2(0.,-t*.05)+A*3.),fbm(q*.5+vec2(5.2,-t*.04)+1.3+A*3.))-.5;     // slow swirl
 vec2 r=q+2.4*sw+vec2(0.,-t*.12);                                                        // and everything rises
 float a=turb(r*1.1);float b=turb(r*2.3+vec2(3.1,-t*.05)+1.8*sw);
 return clamp(a*1.25+.6*b-.36,0.,1.3);}
void tex(vec2 p,float t,out vec3 alb,out vec3 emi,out float den,out float h){
 float tt=t*.05;float N=floor(tt);float fz=tt-N;
 float d=0.,W=0.,pl=0.;
 for(int k=0;k<3;k++){float fk=float(k);float e=fk-fz;float A=fk+N;float f=1.5*exp2(e);
  float x=clamp((e+1.)/3.,0.,1.);float w=.5-.5*cos(6.2832*x);
  vec2 q=rot(A*.9)*p*f+S+A*vec2(13.7,4.1);
  d+=w*puff(q,t,A);pl+=w*vn(q*.3+A);W+=w;}
 W=max(W,1e-3);d/=W;pl/=W;
 float body=smoothstep(.14,.55,d);
 h=.1+.75*smoothstep(.1,.85,d);
 float up=smoothstep(.55,-.5,p.y);                                  // the glow sits low in the frame
 vec3 warm=mix(vec3(1.,.55,.2),uA*1.6,.3);
 vec3 ash=mix(vec3(.22,.22,.25),vec3(.78,.78,.8),smoothstep(.15,.85,d))*mix(vec3(1.),uA*1.7,.12);
 alb=mix(vec3(.025,.028,.04),ash,body);
 float rimL=smoothstep(.15,.5,d)*(1.-smoothstep(.5,.9,d));         // thin edges catch the glow
 emi=warm*(rimL*.6+body*.1)*up*(.5+.9*pl)+pal(.55)*body*.02;
 den=body*38.;}
