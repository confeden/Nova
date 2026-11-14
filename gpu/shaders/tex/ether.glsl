// Ether: luminous filaments (the version the owner liked: no dark patches). Three thread families cover everything, and a broad haze fills the gaps;
// where the ether is thick three more families switch ON (they only add, never subtract), so crowded threads glow stronger.
float thr(vec2 q,float t){vec2 i=q;float c=1.;float inten=.005;
 for(int n=0;n<5;n++){float tt=t*.35*(1.-(3.5/float(n+1)));
  i=q+vec2(cos(tt-i.x)+sin(tt+i.y),sin(tt-i.y)+cos(tt+i.x));
  c+=1./length(vec2(q.x/(sin(i.x+tt)/inten),q.y/(cos(i.y+tt)/inten)));}
 c/=5.;c=1.17-pow(c,1.4);return clamp(pow(abs(c),8.),0.,1.5);}
void tex(vec2 p,float t,out vec3 alb,out vec3 emi,out float den,out float h){
 vec2 q=rot(t*.012)*p;float n1=fbm(q*1.3+S+vec2(t*.02,-t*.015));
 float k1=thr(q*5.5-250.+S*.01+n1*1.2,t);
 float k2=thr(rot(1.1)*q*9.-180.+n1*2.,t*1.3+7.);
 float k3=thr(rot(2.3)*q*2.8-320.+n1*.6,t*.7+3.);
 float m4=smoothstep(.25,.5,fbm(q*1.2+S+53.+vec2(t*.01,0.)));
 float m5=smoothstep(.3,.52,fbm(q*.9+S+23.-vec2(0.,t*.012)));
 float k4=thr(rot(-.7)*q*7.-90.+n1*1.6+S*.02,t*.9+13.)*m4;
 float k5=thr(rot(.4)*q*3.9+140.+n1*.9,t*.55+29.)*m5;
 float k6=thr(rot(-1.6)*q*6.3-210.+n1*1.3+S*.015,t*.8+41.);
 float neb=fbm(q*2.+n1*2.+t*.03);
 float cl=smoothstep(.3,2.4,k1+k2*.6+k3+k4+k5+k6);
 alb=mix(vec3(.02,.03,.07),pal(neb*.8+.5)*.35,neb)+pal(.3+n1*.4)*cl*.1;
 emi=pal(.05+n1*.5+t*.008)*k1*1.7+pal(.4+neb*.4)*k2*.8+pal(.75+n1*.3)*k3*k3*1.1+pal(.55+n1*.3)*k4*.9+pal(.2+n1*.5)*k5*k5*.9
    +pal(.45+n1*.4)*k6*k6*.8
    +pal(.15+neb*.5)*cl*cl*.3+mix(uA,pal(.1+n1*.4),.45)*(.27+.08*neb);       // an even coloured floor: no grey-dark gaps between the threads
 h=.3+.3*k1+.2*k3;den=2.+neb*6.+cl*4.;}
