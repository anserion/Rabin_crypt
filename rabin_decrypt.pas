//Copyright 2017 Andrey S. Ionisyan (anserion@gmail.com)
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.

//учебный шаблон декодирования по криптосистеме Рабина

//в данной программе производится нарезка входного бинарного кода
//на блоки размером, совпадающим с размером модуля деления (в битах),
//так как после этапа кодирования каждый из таких блоков
//гарантированно будет иметь числовое значение, меньшее числового
//значения модуля деления.
//Выходной бинарный код компонуется из блоков, размером на 1 бит меньше
//размера модуля деления, так как при правильном декодировании будут
//получаться блоки с нулем в старшем разряде блока
//-------------------------------------------------------------------

//C(s)=s^2 mod n - кодирование Рабина
//s - исходное сообщение, С - выходной код
//n - открытый ключ (n=p*q), где p,q (простые числа) - закрытый ключ
//p,q сравнимы с 3 по модулю 4
//криптостойкость алгоритма основана на сложности операции
//извлечения корня квадратного в конечных полях

//декодирование Рабина неоднозначное (4 возможных ответа r1,r2,s1,s2)
// r1 = (p*y_p*m_q + q*y_q*m_p) mod n
// r2 = n - r1
// s1 = (p*y_p*m_q - q*y_q*m_p) mod n
// s2 = n - s1
// где
// m_p = c^{(p+1)/4} mod p
// m_q = c^{(q+1)/4} mod q
// y_p и y_q ищутся по расширенному алгоритму Евклида
// из уравнения p*y_p+q*y_q = 1 (отрицательные значения y_p и y_q разрешены)
//-------------------------------------------------------------------
program rabin_decrypt;

//расширенный алгоритм Евклида
function gcdex(a,b:integer; var x,y:integer):integer;
var x1,y1,d:integer;
begin
   if a=0 then 
   begin
      x:=0; y:=1;
      gcdex:=b;
   end else
   begin
      d:=gcdex(b mod a, a, x1, y1);
      x:=y1-(b div a)*x1;
      y:=x1;
      gcdex:=d;
   end;
end;

var
   n,p,q:integer; //ключи кодирования-декодирования
   s,ss:string; //входной битовый вектор и его блок
   cc:string; //блок выходного битового вектора 
              // склеивание этих блоков не имеет смысла, так как на каждом шаге
              // число возможных вариантов склейки увеличивается  4 раза
   s_dec:integer; //входное число (блок) для возведения в квадрат
   c_dec:integer; //результат (для отдельного блока) в числовой форме
   y_p,y_q,m_p,m_q:integer; //переменные математической модели
   i,j,n_size,blocks_num,align_s,pow_tmp,tmp:integer; //вспомогательные переменные
begin
   //ввод исходных данных
   writeln('Rabin decoder');
   writeln('p,q - private key (p,q - prime and "p mod 4 = 3, q mod 4 = 3" ');
   writeln('s - text (binary code)');
   //ввод закрытого ключа
   write('p='); readln(p);
   write('q='); readln(q);
   //расчет вспомогательных параметров математической модели
   tmp:=gcdex(p,q,y_p,y_q);
   writeln('y_p=',y_p);
   writeln('y_q=',y_q);
   //расчет открытого ключа (модуля для вычисления остатка)
   n:=p*q;
   writeln('open key: n=',n);

   //вычисление размера блока
   n_size:=0; tmp:=1; while tmp<n do begin tmp:=tmp*2; n_size:=n_size+1; end;
   writeln('input block size=',n_size);
   writeln('output block size=',n_size-1);
   //ввод бинарного кода для разбиения на блоки и обработки
   write('s=');readln(s);
   //выравнивание входного бинарного кода путем добавления нулей слева
   align_s:=n_size-(length(s) mod n_size);
   if align_s=n_size then align_s:=0;
   for i:=1 to align_s do s:='0'+s;
   //печать выровненного входного бинарного кода
   writeln('===========================');
   writeln('add ',align_s,' zero bits to S');
   for i:=1 to length(s) do
   begin
      write(s[i]);
      if (i mod n_size)=0 then write(' ');
   end;
   writeln;
   writeln('===========================');

   //расчет числа блоков
   blocks_num:=length(s) div n_size;
   for i:=1 to blocks_num do
   begin
      //вырезаем блок из выровненного входного бинарного кода
      //и добавляем нуль слева, чтобы избежать превышения n
      ss:='';
      for j:=1 to n_size do ss:=ss+s[(i-1)*n_size+j];
      //переводим блок из текстового (бинарного) в числовой формат
      s_dec:=0;
      for j:=1 to n_size do
      begin
         s_dec:=s_dec*2;
         if ss[j]='1' then s_dec:=s_dec+1;
      end;
      
      //собственно декодирование Рабина
      //m_p:=s_dec^(p+1)/4 mod p;
      //быстрое возведение в степень с нахождением остатка на каждом шаге 
      m_p:=1; pow_tmp:=(p+1) div 4; tmp:=s_dec;
      while pow_tmp>0 do
         if (pow_tmp mod 2)=0 then
         begin
            tmp:=(tmp*tmp) mod p;
            pow_tmp:=pow_tmp div 2;
         end else
         begin
            m_p:=(m_p*tmp) mod p;
            pow_tmp:=pow_tmp-1;
         end;
      
      //m_q:=s_dec^(q+1)/4 mod q;
      //быстрое возведение в степень с нахождением остатка на каждом шаге 
      m_q:=1; pow_tmp:=(q+1) div 4; tmp:=s_dec;
      while pow_tmp>0 do
         if (pow_tmp mod 2)=0 then
         begin
            tmp:=(tmp*tmp) mod q;
            pow_tmp:=pow_tmp div 2;
         end else
         begin
            m_q:=(m_q*tmp) mod q;
            pow_tmp:=pow_tmp-1;
         end;
      
      //печать промежуточного результата
      writeln('   block',i:3,': m_p=',m_p,' m_q=',m_q);
      
      //первый вариант декодирования
      c_dec:=(p*y_p*m_q+q*y_q*m_p) mod n;
      if c_dec<0 then c_dec:=c_dec+n;
      //перевод выходного блока из числового в текстовый (бинарный) формат
      //(на 1 бит меньше размера входного блока)
      cc:=''; tmp:=c_dec;
      for j:=1 to n_size-1 do
      begin
         if (tmp mod 2)=1 then cc:='1'+cc else cc:='0'+cc;
         tmp:=tmp div 2;
      end;
      //печать промежуточного результата
      writeln('1: block',i:3,': s=',ss,'=',s_dec:4,'    c=',cc,'=',c_dec:4);
      
      //второй вариант декодирования
      c_dec:=n-c_dec;
      //перевод выходного блока из числового в текстовый (бинарный) формат
      //(на 1 бит меньше размера входного блока)
      cc:=''; tmp:=c_dec;
      for j:=1 to n_size-1 do
      begin
         if (tmp mod 2)=1 then cc:='1'+cc else cc:='0'+cc;
         tmp:=tmp div 2;
      end;
      //печать промежуточного результата
      writeln('2: block',i:3,': s=',ss,'=',s_dec:4,'    c=',cc,'=',c_dec:4);

      //третий вариант декодирования
      c_dec:=(p*y_p*m_q-q*y_q*m_p) mod n;
      if c_dec<0 then c_dec:=c_dec+n;
      //перевод выходного блока из числового в текстовый (бинарный) формат
      //(на 1 бит меньше размера входного блока)
      cc:=''; tmp:=c_dec;
      for j:=1 to n_size-1 do
      begin
         if (tmp mod 2)=1 then cc:='1'+cc else cc:='0'+cc;
         tmp:=tmp div 2;
      end;
      //печать промежуточного результата
      writeln('3: block',i:3,': s=',ss,'=',s_dec:4,'    c=',cc,'=',c_dec:4);

      //четвертый вариант декодирования
      c_dec:=n-c_dec;
      //перевод выходного блока из числового в текстовый (бинарный) формат
      //(на 1 бит меньше размера входного блока)
      cc:=''; tmp:=c_dec;
      for j:=1 to n_size-1 do
      begin
         if (tmp mod 2)=1 then cc:='1'+cc else cc:='0'+cc;
         tmp:=tmp div 2;
      end;
      //печать промежуточного результата
      writeln('4: block',i:3,': s=',ss,'=',s_dec:4,'    c=',cc,'=',c_dec:4);
   end;
   writeln('===========================');
end.
