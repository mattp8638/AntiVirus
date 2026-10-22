import type { ReactNode } from "react";

type Column<T> = {
  header: string;
  accessor: (row: T) => ReactNode;
};

type DataTableProps<T> = {
  caption: string;
  columns: Column<T>[];
  rows: T[];
};

const DataTable = <T,>({ caption, columns, rows }: DataTableProps<T>) => (
  <table className="data-table">
    <caption>{caption}</caption>
    <thead>
      <tr>
        {columns.map((column) => (
          <th key={column.header} scope="col">
            {column.header}
          </th>
        ))}
      </tr>
    </thead>
    <tbody>
      {rows.map((row, rowIndex) => (
        <tr key={`row-${rowIndex}`}>
          {columns.map((column) => (
            <td key={`${column.header}-${rowIndex}`}>{column.accessor(row)}</td>
          ))}
        </tr>
      ))}
    </tbody>
  </table>
);

export default DataTable;
