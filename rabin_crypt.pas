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

//учебный шаблон кодирования по криптосистеме Рабина

//в данной программе производится нарезка входного бинарного кода
//на блоки размером на 1 бит меньше, чем размер модуля деления (в битах)
//и дополнение блока нулем к старшему разряду,
//так как нет гарантии, что числовое значения входного блока будет
//меньше, чем числовой размером модуля деления при равном числе битов.
//Выходной бинарный код компонуется из блоков, размером совпадающим с
//размером модуля деления (так как числовое значение каждого из них
//гарантированно меньше значения модуля деления)

//алгоритм кодирования Рабина
//C(s)=s^2 mod n
//s - исходное сообщение, С - выходной код
//n - открытый ключ (n=p*q), где p,q (простые числа) - закрытый ключ
//p,q сравнимы с 3 по модулю 4 (в данной программе не генерируются)
//криптостойкость алгоритма основана на сложности операции
//извлечения корня квадратного в конечных полях
program rabin_crypt;
var
   n:integer; //входной открытый ключ для кодирования
   s,ss:string; //входной битовый вектор и его блок
   c,cc:string; //выходной битовый вектор и его блок
   s_dec:integer; //входное число (блок) для возведения в квадрат
   c_dec:integer; //результат (для отдельного блока) в числовой форме
   i,j,n_size,blocks_num,align_s,tmp:integer; //вспомогательные переменные
begin
   //ввод исходных данных
   writeln('Rabin coder');
   writeln('n - open key, s - text (binary code)');
   //ввод открытого ключа (модуля для вычисления остатка)
   write('n='); readln(n);
   //вычисление размера блока
   n_size:=0; tmp:=1; while tmp<n do begin tmp:=tmp*2; n_size:=n_size+1; end;
   writeln('input block size=',n_size-1);
   writeln('output block size=',n_size);
   //ввод бинарного кода для разбиения на блоки и дальнейшей обработки
   write('s=');readln(s);
   //выравнивание входного бинарного кода путем добавления
   //границы "01" и нулей для выравнивания слева
   s:='01'+s;
   align_s:=(n_size-1)-(length(s) mod (n_size-1));
   if align_s=n_size-1 then align_s:=0;
   for i:=1 to align_s do s:='0'+s;
   //печать выровненного входного бинарного кода
   writeln('===========================');
   writeln('add ',align_s,' zero bits and 01 to S');
   for i:=1 to length(s) do
   begin
      write(s[i]);
      if (i mod (n_size-1))=0 then write(' ');
   end;
   writeln;
   writeln('===========================');

   //расчет числа блоков
   blocks_num:=length(s) div (n_size-1);
   c:='';
   for i:=1 to blocks_num do
   begin
      //вырезаем блок из выровненного входного бинарного кода
      //и добавляем нуль слева, чтобы избежать превышения n
      ss:='';
      for j:=1 to n_size-1 do ss:=ss+s[(i-1)*(n_size-1)+j];
      ss:='0'+ss;
      //переводим блок из текстового (бинарного) в числовой формат
      s_dec:=0;
      for j:=1 to n_size do
      begin
         s_dec:=s_dec*2;
         if ss[j]='1' then s_dec:=s_dec+1;
      end;
      
      //возведение в квадрат с нахождением остатка от деления на n (код Рабина)
      c_dec:=(s_dec*s_dec) mod n;

      //перевод выходного блока из числового в текстовый (бинарный) формат
      cc:=''; tmp:=c_dec;
      for j:=1 to n_size do
      begin
         if (tmp mod 2)=1 then cc:='1'+cc else cc:='0'+cc;
         tmp:=tmp div 2;
      end;
      //наращивание окончательного ответа
      c:=c+cc;
      //печать промежуточного результата
      writeln('block',i:3,': s=',ss,'=',s_dec:4,'    c=',cc,'=',c_dec:4);
   end;
   //печать окончательного результата
   writeln('===========================');
   writeln('binary result');
   writeln(c);
end.
