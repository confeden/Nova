// Water: caustics on a tiled pool floor from a sum of drifting plane waves. Twelve waves with irregular directions and
// wavelengths (no regular fan), each with its own slowly changing strength, plus patchy swell strength in space, and
// the glints' width/brightness varies from place to place, so the bright network is a mix of hair-fine threads, wide
// ribbons and soft pools instead of a uniform mesh of worms. Everything drifts slowly.
void tex(vec2 p,float t,out vec3 alb,out vec3 emi,out float den,out float h){
 t*=24.;                                                                   // owner: at slider 25 the water must run ~2x faster than the old build did at 200
 vec2 q=p*9.5+S*.2;q+=1.1*vec2(fbm(q*.3+t*.004+1.),fbm(q*.3+5.-t*.0035));
 vec2 g=vec2(0);float hxx=0.,hyy=0.,hxy=0.,hh=0.;
 for(int i=0;i<12;i++){float fi=float(i);
  float an=h21(vec2(fi,uSeed+2.))*6.2832+.35*sin(t*.006+fi*2.1)+.8*(vn(q*.12+fi*5.)-.5);
  vec2 d=vec2(cos(an),sin(an));
  float k=1.1+3.6*pow(h21(vec2(fi+.5,uSeed+7.)),1.3);                    // irregular wavelengths
  float swell=.25+1.1*vn(q*.16+fi*3.7+t*.002);                           // each wave is strong only in patches
  float c0=.5/sqrt(1.+fi*.35)*(.4+.9*vn(vec2(fi*3.1+uSeed,t*.004+fi)))*swell;float A=c0/(k*k);
  float ph=k*dot(d,q)+t*(.014+.004*h21(vec2(fi,3.)))*sqrt(k)+fi*4.1+1.1*(vn(q*.4+fi*9.)-.5);
  float s=sin(ph),c=cos(ph);
  hh+=A*s;g+=A*k*d*c;hxx-=c0*d.x*d.x*s;hyy-=c0*d.y*d.y*s;hxy-=c0*d.x*d.y*s;}
 vec3 L=vec3(2.38,2.5,2.62)*(.85+.4*vn(q*.18+4.));
 vec3 det=(1.+L*hxx)*(1.+L*hyy)-L*L*hxy*hxy;
 float wv=.03+.26*pow(vn(q*.4+9.),1.8);float amp=.45+1.1*pow(vn(q*.9+3.),1.3);
 vec3 I=max(.17/(abs(det)+wv*vec3(.9,1.,1.15))-.05,0.)*amp;
 vec2 uvt=p*14.+g*1.6+S;vec2 gr=abs(fract(uvt)-.5);float grout=smoothstep(.44,.49,max(gr.x,gr.y));float tid=h21(floor(uvt));
 alb=mix(mix(vec3(.03,.20,.32),vec3(.06,.34,.46),tid),uA,.12)*(1.-.28*grout);
 emi=I*mix(vec3(.75,.95,1.),pal(.08),.2)*(.8+.2*tid);
 h=.5+hh*.9;den=2.;}
