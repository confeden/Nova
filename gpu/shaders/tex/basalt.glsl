vec3 vhex(vec2 p){vec2 s=vec2(1.,1.732);float d1=8.,d2=8.,idh=0.;
 for(int k=0;k<2;k++){vec2 off=float(k)*.5*s;vec2 b=floor((p-off)/s);
  for(int y=-1;y<=1;y++)for(int x=-1;x<=1;x++){vec2 c=b+vec2(float(x),float(y));
   vec2 pt=c*s+off+(h22(c+float(k)*37.+uSeed)-.5)*.3;float d=length(p-pt);
   if(d<d1){d2=d1;d1=d;idh=h21(c+float(k)*37.+1.3);}else if(d<d2)d2=d;}}
 return vec3(d1,d2-d1,idh);}
void tex(vec2 p,float t,out vec3 alb,out vec3 emi,out float den,out float h){
 vec2 q=p*4.4+S+vec2(t*.05,t*.028);q+=.10*vec2(fbm(q*1.5),fbm(q*1.5+7.));
 vec3 v=vhex(q);float e=smoothstep(.075,.015,v.y);
 float lift=.5+.5*sin(t*.45+v.z*40.);
 float flow=fbm(q*.55+vec2(-t*.20,t*.09));
 float lava=smoothstep(.36,.66,flow+.18*sin(t*.5+q.x*.9+q.y*.6));
 float top=fbm(q*9.+v.z*30.);
 h=(1.-e)*(.3+.6*lift)+top*.08;
 alb=mix(vec3(.07,.075,.09),vec3(.22,.22,.26),lift)*(.7+.6*top)+uBg*.6;
 float rim=smoothstep(.24,0.,v.y)*(1.-e);
 emi=mix(pal(.02+flow*.5+t*.01),vec3(1.,.45,.12),.3)*(e*(.22+3.4*lava)+rim*lava*.6*(1.-lift));
 den=(1.-e)*(30.+50.*lift);}