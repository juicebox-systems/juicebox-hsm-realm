use std::cmp::max;
use std::fmt::{Result, Write};
use std::iter::zip;

pub struct Table {
    // invariant: columns, widths and the vec's inside rows are all the same length
    columns: Vec<Column>,
    rows: Vec<Vec<String>>,
    widths: Vec<usize>,
    style: TableStyle,
}

impl Table {
    pub fn new<const N: usize>(
        columns: [impl Into<Column>; N],
        rows: impl IntoIterator<Item = [impl Into<String>; N]>,
        style: TableStyle,
    ) -> Self {
        let columns: Vec<Column> = columns.into_iter().map(|t| t.into()).collect();
        let mut widths: Vec<usize> = columns.iter().map(|t| t.title.len()).collect();
        let rows: Vec<_> = rows
            .into_iter()
            .map(|row| row.into_iter().map(|c| c.into()).collect::<Vec<String>>())
            .collect();
        for row in &rows {
            for (cell, width) in zip(row.iter(), widths.iter_mut()) {
                *width = max(*width, cell.len());
            }
        }
        Table {
            columns,
            rows,
            widths,
            style,
        }
    }

    pub fn render(&self, out: &mut impl Write) -> Result {
        let separator_row = self.separator_row();
        out.write_str(&separator_row)?;

        let mut buff = String::with_capacity(separator_row.len());
        self.render_row(&mut buff, &mut self.columns.iter().map(|c| &c.title));
        out.write_str(&buff)?;
        out.write_str(&separator_row)?;

        for row in &self.rows {
            buff.clear();
            self.render_row(&mut buff, &mut row.iter());
            out.write_str(&buff)?;
        }
        out.write_str(&separator_row)
    }

    fn separator_row(&self) -> String {
        let mut out = String::new();
        if self.style.borders == Borders::None {
            return out;
        }
        let (start_end_delim, cell_delim) = self.style.borders.separator_delims();
        out.push_str(start_end_delim);
        for (col, w) in self.widths.iter().enumerate() {
            for _ in 0..(*w + self.style.borders.cell_padding() * 2) {
                out.push('-');
            }
            if col == self.widths.len() - 1 {
                out.push_str(start_end_delim);
            } else {
                out.push_str(cell_delim);
            }
        }
        out.push('\n');
        out
    }

    fn render_row(&self, buff: &mut String, row: &mut dyn Iterator<Item = &String>) {
        let (start_end_delim, cell_delim) = self.style.borders.text_delims();
        buff.push_str(start_end_delim);
        let padding = self.style.borders.cell_padding();
        for (col, cell) in row.enumerate() {
            for _ in 0..padding {
                buff.push(' ');
            }
            let width = self.widths[col];
            match self.columns[col].justify {
                Justify::Left => write!(buff, "{cell:<width$}").unwrap(),
                Justify::Center => write!(buff, "{cell:^width$}").unwrap(),
                Justify::Right => write!(buff, "{cell:>width$}").unwrap(),
            }
            for _ in 0..padding {
                buff.push(' ');
            }
            if col < self.columns.len() - 1 {
                buff.push_str(cell_delim);
            } else {
                buff.push_str(start_end_delim);
                buff.push('\n');
            }
        }
    }
}

pub struct Column {
    pub title: String,
    pub justify: Justify,
}

impl Column {
    pub fn new(title: impl Into<String>) -> Self {
        Column {
            title: title.into(),
            justify: Justify::Left,
        }
    }

    pub fn justify(mut self, j: Justify) -> Self {
        self.justify = j;
        self
    }
}

#[derive(Default)]
pub enum Justify {
    #[default]
    Left,
    Center,
    Right,
}

#[derive(Default)]
pub struct TableStyle {
    pub borders: Borders,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Borders {
    // No border at all.
    None,
    // A border around the outer edge of the table and under the title row.
    #[default]
    Table,
    // A border around every cell in the table.
    Cells,
}

impl Borders {
    // The amount of padding that should appear on the left and right side of
    // each cell in the table.
    fn cell_padding(&self) -> usize {
        match self {
            Borders::None => 0,
            Borders::Table => 1,
            Borders::Cells => 1,
        }
    }

    // The delimiters, the first is the row start/end delimiter, the second is
    // the inter cell delimiter.
    fn text_delims(&self) -> (&str, &str) {
        match self {
            Borders::None => ("", " "),
            Borders::Table => ("|", ""),
            Borders::Cells => ("|", "|"),
        }
    }

    // The row and cell delimiters for the separator row.
    fn separator_delims(&self) -> (&str, &str) {
        match self {
            Borders::None => ("", "-"),
            Borders::Table => ("+", ""),
            Borders::Cells => ("+", "+"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use expect_test::expect_file;

    #[test]
    fn borders() {
        let mut out = String::new();
        let borders = [Borders::None, Borders::Table, Borders::Cells];
        for border in borders {
            Table::new(
                [
                    Column::new("a"),
                    Column::new("be"),
                    Column::new("a long title"),
                ],
                [
                    ["one", "two", "three"],
                    ["four", "five", "six"],
                    ["seven", "", "nine"],
                ],
                TableStyle { borders: border },
            )
            .render(&mut out)
            .unwrap();
            out.push('\n');
        }
        expect_file!["../borders.txt"].assert_eq(&out);
    }

    #[test]
    fn justify() {
        let mut out = String::new();
        Table::new(
            [
                Column::new("a").justify(Justify::Right),
                Column::new("be"),
                Column::new("a long title").justify(Justify::Center),
            ],
            [["one", "two", "three"], ["four", "five", "six"]],
            TableStyle::default(),
        )
        .render(&mut out)
        .unwrap();
        expect_file!["../justify.txt"].assert_eq(&out);
    }
}
